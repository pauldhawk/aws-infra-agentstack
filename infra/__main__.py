"""Pulumi program to provision infrastructure for n8n, Zep, Qdrant and Aurora.

This program creates a dedicated VPC with public and private subnets, an EC2
instance to host Dockerised services (n8n, Zep and Qdrant), an Aurora
Serverless v2 PostgreSQL cluster, Secrets Manager secrets for credentials,
and an S3 bucket for backups.  Many values are configurable via stack
configuration (see Pulumi.dev.yaml) and can be overridden with `pulumi config`.

The code is deliberately conservative: it illustrates one way to assemble
these resources but leaves room for extension (e.g. adding TLS termination,
monitoring, API Gateway, etc.).  Comments marked with TODO indicate
enhancements described in the task specification.
"""

import base64
import json

import pulumi
import pulumi_aws as aws

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

config = pulumi.Config()
aws_region = config.get("aws:region") or aws.config.region

# Names for secrets stored in Secrets Manager.  In a real deployment, the
# secret values should be set via `pulumi config set --secret <key>` to
# encrypt them in the state file.  Here we fetch the names from config to
# create placeholder secrets if they don't already exist.
n8n_secret_name = config.get("n8n:secretName") or "n8n/credentials"
qdrant_secret_name = config.get("qdrant:secretName") or "qdrant/credentials"
aurora_master_username = config.get("aurora:masterUsername") or "dbadmin"
aurora_master_password = config.get_secret("aurora:masterPassword") or pulumi.secret("changeme123!")

# -----------------------------------------------------------------------------
# VPC and networking
# -----------------------------------------------------------------------------

# Create a new VPC with a CIDR block large enough for a handful of subnets.
vpc = aws.ec2.Vpc(
    "app-vpc",
    cidr_block="10.0.0.0/16",
    enable_dns_hostnames=True,
    tags={"Name": pulumi.get_project() + "-vpc"},
)

# Internet gateway for public subnets
igw = aws.ec2.InternetGateway(
    "app-igw",
    vpc_id=vpc.id,
    tags={"Name": pulumi.get_project() + "-igw"},
)

# Get two availability zones to spread subnets.  If the region has fewer
# availability zones, Pulumi will return as many as are available.
availability_zones = aws.get_availability_zones().names[:2]

public_subnets = []
private_subnets = []
public_route_table_assocs = []
private_route_table_assocs = []

for i, az in enumerate(availability_zones):
    # Public subnet
    pub_subnet = aws.ec2.Subnet(
        f"public-subnet-{i}",
        vpc_id=vpc.id,
        cidr_block=f"10.0.{i}.0/24",
        availability_zone=az,
        map_public_ip_on_launch=True,
        tags={"Name": f"public-{az}"},
    )
    public_subnets.append(pub_subnet)

    # Elastic IP and NAT gateway for this AZ
    eip = aws.ec2.Eip(f"nat-eip-{i}", vpc=True)
    nat_gw = aws.ec2.NatGateway(
        f"nat-gw-{i}",
        allocation_id=eip.id,
        subnet_id=pub_subnet.id,
        tags={"Name": f"nat-{az}"},
    )

    # Public route table and association
    public_route_table = aws.ec2.RouteTable(
        f"public-rt-{i}",
        vpc_id=vpc.id,
        routes=[
            aws.ec2.RouteTableRouteArgs(
                cidr_block="0.0.0.0/0",
                gateway_id=igw.id,
            )
        ],
        tags={"Name": f"public-rt-{az}"},
    )
    pub_assoc = aws.ec2.RouteTableAssociation(
        f"public-rt-assoc-{i}",
        subnet_id=pub_subnet.id,
        route_table_id=public_route_table.id,
    )
    public_route_table_assocs.append(pub_assoc)

    # Private subnet
    priv_subnet = aws.ec2.Subnet(
        f"private-subnet-{i}",
        vpc_id=vpc.id,
        cidr_block=f"10.0.{i+10}.0/24",
        availability_zone=az,
        map_public_ip_on_launch=False,
        tags={"Name": f"private-{az}"},
    )
    private_subnets.append(priv_subnet)

    # Private route table using NAT gateway
    private_route_table = aws.ec2.RouteTable(
        f"private-rt-{i}",
        vpc_id=vpc.id,
        routes=[
            aws.ec2.RouteTableRouteArgs(
                cidr_block="0.0.0.0/0",
                nat_gateway_id=nat_gw.id,
            )
        ],
        tags={"Name": f"private-rt-{az}"},
    )
    priv_assoc = aws.ec2.RouteTableAssociation(
        f"private-rt-assoc-{i}",
        subnet_id=priv_subnet.id,
        route_table_id=private_route_table.id,
    )
    private_route_table_assocs.append(priv_assoc)

# -----------------------------------------------------------------------------
# Security Groups
# -----------------------------------------------------------------------------

# EC2 security group allowing SSH, HTTP and HTTPS from the internet and all
# traffic within the VPC
ec2_sg = aws.ec2.SecurityGroup(
    "app-ec2-sg",
    vpc_id=vpc.id,
    description="Allow HTTPS and SSH inbound; allow all egress",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp", from_port=22, to_port=22, cidr_blocks=["0.0.0.0/0"],
        ),
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp", from_port=80, to_port=80, cidr_blocks=["0.0.0.0/0"],
        ),
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp", from_port=443, to_port=443, cidr_blocks=["0.0.0.0/0"],
        ),
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp", from_port=0, to_port=65535, cidr_blocks=[vpc.cidr_block],
            description="internal traffic",
        ),
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"],
        ),
    ],
    tags={"Name": "ec2-sg"},
)

# Database security group allowing connections from EC2 instances
db_sg = aws.ec2.SecurityGroup(
    "app-db-sg",
    vpc_id=vpc.id,
    description="Allow traffic from EC2 instances to Aurora",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp", from_port=5432, to_port=5432,
            security_groups=[ec2_sg.id],
        ),
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"],
        ),
    ],
    tags={"Name": "db-sg"},
)

# -----------------------------------------------------------------------------
# Secrets Manager Secrets
# -----------------------------------------------------------------------------

def ensure_secret(secret_name: str) -> aws.secretsmanager.Secret:
    """Ensure a secret exists with the given name."""
    return aws.secretsmanager.Secret(
        secret_name.replace("/", "-"),
        name=secret_name,
    )


n8n_secret = ensure_secret(n8n_secret_name)
qdrant_secret = ensure_secret(qdrant_secret_name)
aurora_password_secret = aws.secretsmanager.Secret(
    "aurora-master-password",
    name=f"{pulumi.get_project()}/aurora/masterPassword",
)
aurora_password_version = aws.secretsmanager.SecretVersion(
    "aurora-master-password-version",
    secret_id=aurora_password_secret.id,
    secret_string=aurora_master_password,
)

# -----------------------------------------------------------------------------
# Aurora Serverless v2 PostgreSQL Cluster
# -----------------------------------------------------------------------------

db_subnet_group = aws.rds.SubnetGroup(
    "app-db-subnet-group",
    subnet_ids=[subnet.id for subnet in private_subnets],
    tags={"Name": "app-db-subnet-group"},
)

db_cluster = aws.rds.Cluster(
    "app-aurora-cluster",
    cluster_identifier="app-aurora-cluster",
    engine=aws.rds.EngineType.AURORA_POSTGRESQL,
    engine_mode=aws.rds.EngineMode.PROVISIONED,
    engine_version="13.6",
    database_name="appdb",
    master_username=aurora_master_username,
    master_password=aurora_master_password,
    db_subnet_group_name=db_subnet_group.name,
    vpc_security_group_ids=[db_sg.id],
    storage_encrypted=True,
    serverlessv2_scaling_configuration=aws.rds.ClusterServerlessv2ScalingConfigurationArgs(
        min_capacity=0.5,
        max_capacity=4.0,
        seconds_until_auto_pause=3600,
    ),
    tags={"Name": "app-aurora-cluster"},
)

db_instance = aws.rds.ClusterInstance(
    "app-aurora-instance",
    cluster_identifier=db_cluster.id,
    instance_class="db.serverless",
    engine=db_cluster.engine,
    engine_version=db_cluster.engine_version,
    tags={"Name": "app-aurora-instance"},
)

# -----------------------------------------------------------------------------
# S3 Bucket for backups
# -----------------------------------------------------------------------------

backup_bucket = aws.s3.Bucket(
    "app-backup-bucket",
    bucket=f"{pulumi.get_project()}-backup-{pulumi.get_stack()}",
    versioning=aws.s3.BucketVersioningArgs(enabled=True),
    server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
        rules=[
            aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                    sse_algorithm="AES256"
                )
            )
        ]
    ),
    tags={"Name": "app-backup"},
)

# -----------------------------------------------------------------------------
# IAM role for EC2 instance to read secrets and write backups
# -----------------------------------------------------------------------------

assume_role_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
        }
    ],
})

ec2_role = aws.iam.Role("app-ec2-role", assume_role_policy=assume_role_policy)

ec2_policy = aws.iam.RolePolicy(
    "app-ec2-policy",
    role=ec2_role.id,
    policy=pulumi.Output.all(
        backup_bucket.arn,
        n8n_secret.arn,
        qdrant_secret.arn,
        aurora_password_secret.arn,
    ).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                "Resource": [args[1], args[2], args[3]],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetObject"],
                "Resource": f"{args[0]}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    })),
)

instance_profile = aws.iam.InstanceProfile(
    "app-ec2-instance-profile",
    role=ec2_role.name,
)

# -----------------------------------------------------------------------------
# EC2 Instance to run Docker Compose
# -----------------------------------------------------------------------------

# Get latest Amazon Linux 2 AMI for region
ami = aws.ec2.get_ami(
    most_recent=True,
    owners=["amazon"],
    filters=[{"name": "name", "values": ["amzn2-ami-hvm-*-x86_64-gp2"]}],
)

# Define a user data script.  We use an f-string so that the secret names are
# interpolated into the script.  The script installs Docker and Docker Compose,
# fetches secrets from Secrets Manager and starts the containers.
user_data = f"""
#!/bin/bash
set -eu
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

# Install updates and Docker
yum update -y
yum install -y docker amazon-linux-extras
service docker start
usermod -a -G docker ec2-user

# Install docker-compose
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Prepare application directory
mkdir -p /opt/app

# Retrieve secrets from Secrets Manager
n8n_creds=$(aws secretsmanager get-secret-value --secret-id {n8n_secret_name} --query SecretString --output text || echo "{{}}");
qdrant_creds=$(aws secretsmanager get-secret-value --secret-id {qdrant_secret_name} --query SecretString --output text || echo "{{}}");
aurora_pass=$(aws secretsmanager get-secret-value --secret-id {pulumi.get_project()}/aurora/masterPassword --query SecretString --output text || echo "")

# Write environment file
cat > /opt/app/.env <<EOF
N8N_CREDENTIALS=$n8n_creds
QDRANT_CREDENTIALS=$qdrant_creds
POSTGRES_PASSWORD=$aurora_pass
EOF

# Write docker-compose file
cat > /opt/app/docker-compose.yml <<'EOF'
version: "3.8"
services:
  n8n:
    image: n8nio/n8n:latest
    restart: always
    ports:
      - "80:5678"
    env_file: /opt/app/.env
    volumes:
      - n8n-data:/home/node/.n8n
  zep:
    image: ghcr.io/getzep/zep:latest
    restart: always
    env_file: /opt/app/.env
    ports:
      - "9000:8000"
  qdrant:
    image: qdrant/qdrant:latest
    restart: always
    ports:
      - "6333:6333"
    volumes:
      - qdrant-data:/qdrant/storage

volumes:
  n8n-data:
  qdrant-data:
EOF

cd /opt/app
/usr/local/bin/docker-compose up -d

###############################################################################
# Configure a daily backup of Docker volumes to S3
###############################################################################
# Expose the backup bucket name as an environment variable so that it can
# be referenced from backup scripts.  The value is injected by Pulumi via the
# f-string below.
BACKUP_BUCKET_NAME={backup_bucket.id}

# Create a backup script that syncs the n8n and Qdrant volumes to the S3
# backup bucket.  The EC2 instance role has permissions to write to this
# bucket.  You could replace the paths below if you change the volume names.
cat > /opt/app/backup.sh <<'BACKUP'
#!/bin/bash
set -euo pipefail
export PATH=$PATH:/usr/local/bin

# Synchronise n8n data
if [ -d /var/lib/docker/volumes/n8n-data/_data ]; then
  aws s3 sync /var/lib/docker/volumes/n8n-data/_data s3://$BACKUP_BUCKET_NAME/n8n-backups/ --delete
fi

# Synchronise Qdrant data
if [ -d /var/lib/docker/volumes/qdrant-data/_data ]; then
  aws s3 sync /var/lib/docker/volumes/qdrant-data/_data s3://$BACKUP_BUCKET_NAME/qdrant-backups/ --delete
fi
BACKUP

chmod +x /opt/app/backup.sh

###############################################################################
# Schedule the backup to run daily at 03:30 UTC via cron.  The output will be
# logged to /var/log/backup.log.
echo "30 3 * * * root /opt/app/backup.sh >> /var/log/backup.log 2>&1" >> /etc/crontab

###############################################################################
# TODO: install and configure a reverse proxy (Caddy or Nginx) with Let's Encrypt
# TODO: install and configure the CloudWatch agent for log forwarding and a
# webhook health monitor script.  The instance role grants permission to send
# logs to CloudWatch.
"""

ec2_instance = aws.ec2.Instance(
    "app-ec2-instance",
    instance_type="t3.small",
    ami=ami.id,
    iam_instance_profile=instance_profile.name,
    vpc_security_group_ids=[ec2_sg.id],
    subnet_id=public_subnets[0].id,
    associate_public_ip_address=True,
    user_data=base64.b64encode(user_data.encode()).decode(),
    tags={"Name": "app-ec2-instance"},
)

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

pulumi.export("vpc_id", vpc.id)
pulumi.export("public_subnet_ids", [s.id for s in public_subnets])
pulumi.export("private_subnet_ids", [s.id for s in private_subnets])
pulumi.export("ec2_public_ip", ec2_instance.public_ip)
pulumi.export("aurora_endpoint", db_cluster.endpoint)
pulumi.export("backup_bucket_name", backup_bucket.id)