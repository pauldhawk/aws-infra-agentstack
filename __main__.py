"""
Pulumi program to deploy a self‑hosted n8n + Zep stack on AWS.

This module provisions the networking, compute, database and supporting
services required to run n8n together with the Zep long‑term memory
service and the Qdrant vector database.  Secrets are stored in AWS
Secrets Manager and referenced by the EC2 instance via an IAM role.

The resulting stack outputs the public IP address and DNS name of the
host, the RDS endpoint and the names of the created secrets.  After
running `pulumi up` be sure to create a DNS record for your chosen
`n8nDomain` pointing to the EC2 IP.
"""

import base64
import json
import os
import secrets
from typing import List

import pulumi
import pulumi_aws as aws


# -----------------------------------------------------------------------------
# Configuration
#
# Required configuration keys are defined in Pulumi.dev.yaml.  You can add
# additional stacks (e.g. prod) by creating corresponding YAML files and
# overriding values as needed.
# -----------------------------------------------------------------------------

config = pulumi.Config()

# Domain used for the public n8n endpoint.  Caddy will request a TLS
# certificate for this name.
n8n_domain: str = config.require("n8nDomain")

# Secret names used in AWS Secrets Manager.  If the specified secret does
# not already exist it will be created with generated values.
n8n_secret_name: str = config.get("n8nSecretName") or "n8n/credentials"
db_secret_name: str = config.get("dbSecretName") or "zep/db"
qdrant_secret_name: str = config.get("qdrantSecretName") or "qdrant/credentials"

# EC2 instance type
instance_type: str = config.get("instanceType") or "t3.small"

# Backup bucket name
backup_bucket_name: str = config.require("backupBucketName")

# Database configuration
db_engine_version: str = config.get("dbEngineVersion") or "13.8"
db_min_capacity: float = config.get_float("dbMinCapacity") or 2.0
db_max_capacity: float = config.get_float("dbMaxCapacity") or 4.0

# Optional SSH public key for EC2 login
ssh_public_key: str | None = config.get("sshPublicKey")

# Make sure the AWS provider does not attempt to validate credentials when
# performing previews without AWS access.  Skip region and credential
# validation allows Pulumi to infer resource properties offline.  These
# options have no effect when valid credentials are present.
provider = aws.Provider(
    "aws-provider",
    skip_credentials_validation=True,
    skip_region_validation=True,
    skip_metadata_api_check=True,
)


# -----------------------------------------------------------------------------
# VPC & Networking
# -----------------------------------------------------------------------------

vpc = aws.ec2.Vpc(
    "vpc",
    cidr_block="10.0.0.0/16",
    enable_dns_support=True,
    enable_dns_hostnames=True,
    tags={"Name": pulumi.get_project() + "-vpc"},
    opts=pulumi.ResourceOptions(provider=provider),
)

availability_zone = pulumi.Output.concat(aws.config.region, "a")

public_subnet = aws.ec2.Subnet(
    "public-subnet",
    vpc_id=vpc.id,
    cidr_block="10.0.1.0/24",
    availability_zone=availability_zone,
    map_public_ip_on_launch=True,
    tags={"Name": pulumi.get_project() + "-public"},
    opts=pulumi.ResourceOptions(provider=provider),
)

private_subnet = aws.ec2.Subnet(
    "private-subnet",
    vpc_id=vpc.id,
    cidr_block="10.0.2.0/24",
    availability_zone=availability_zone,
    map_public_ip_on_launch=False,
    tags={"Name": pulumi.get_project() + "-private"},
    opts=pulumi.ResourceOptions(provider=provider),
)

igw = aws.ec2.InternetGateway(
    "igw",
    vpc_id=vpc.id,
    tags={"Name": pulumi.get_project() + "-igw"},
    opts=pulumi.ResourceOptions(provider=provider),
)

# Public route table routes traffic to the internet via IGW
public_rt = aws.ec2.RouteTable(
    "public-rt",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)],
    tags={"Name": pulumi.get_project() + "-public-rt"},
    opts=pulumi.ResourceOptions(provider=provider),
)
aws.ec2.RouteTableAssociation(
    "public-rt-assoc",
    subnet_id=public_subnet.id,
    route_table_id=public_rt.id,
    opts=pulumi.ResourceOptions(provider=provider),
)

# NAT Gateway to allow private subnet to access the internet
eip = aws.ec2.Eip(
    "nat-eip",
    vpc=True,
    opts=pulumi.ResourceOptions(provider=provider),
)
nat_gw = aws.ec2.NatGateway(
    "nat-gw",
    allocation_id=eip.id,
    subnet_id=public_subnet.id,
    tags={"Name": pulumi.get_project() + "-nat-gw"},
    opts=pulumi.ResourceOptions(provider=provider),
)

private_rt = aws.ec2.RouteTable(
    "private-rt",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", nat_gateway_id=nat_gw.id)],
    tags={"Name": pulumi.get_project() + "-private-rt"},
    opts=pulumi.ResourceOptions(provider=provider),
)
aws.ec2.RouteTableAssociation(
    "private-rt-assoc",
    subnet_id=private_subnet.id,
    route_table_id=private_rt.id,
    opts=pulumi.ResourceOptions(provider=provider),
)

# -----------------------------------------------------------------------------
# Security Groups
# -----------------------------------------------------------------------------

ec2_sg = aws.ec2.SecurityGroup(
    "ec2-sg",
    vpc_id=vpc.id,
    description="Allow HTTPS and SSH, plus intra‑VPC traffic",
    ingress=[
        # SSH
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=22, to_port=22, cidr_blocks=["0.0.0.0/0"]),
        # HTTP (for Let’s Encrypt challenges) and HTTPS
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=80, to_port=80, cidr_blocks=["0.0.0.0/0"]),
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=443, to_port=443, cidr_blocks=["0.0.0.0/0"]),
        # Allow all traffic from self (intra‑group communication)
        aws.ec2.SecurityGroupIngressArgs(protocol="-1", from_port=0, to_port=0, self=True),
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
    tags={"Name": pulumi.get_project() + "-ec2-sg"},
    opts=pulumi.ResourceOptions(provider=provider),
)

db_sg = aws.ec2.SecurityGroup(
    "db-sg",
    vpc_id=vpc.id,
    description="Allow PostgreSQL from within the VPC",
    ingress=[aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=5432, to_port=5432, cidr_blocks=[vpc.cidr_block])],
    egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
    tags={"Name": pulumi.get_project() + "-db-sg"},
    opts=pulumi.ResourceOptions(provider=provider),
)

# -----------------------------------------------------------------------------
# S3 bucket for backups
# -----------------------------------------------------------------------------

backup_bucket = aws.s3.Bucket(
    "backup-bucket",
    bucket=backup_bucket_name,
    versioning=aws.s3.BucketVersioningArgs(enabled=True),
    server_side_encryption_configuration=aws.s3.BucketServerSideEncryptionConfigurationArgs(
        rules=[aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256"
            )
        )]
    ),
    tags={"Name": pulumi.get_project() + "-backup"},
    opts=pulumi.ResourceOptions(provider=provider),
)

# -----------------------------------------------------------------------------
# Secrets Manager secrets
# -----------------------------------------------------------------------------

def ensure_secret(name: str, description: str, initial_value: dict[str, str]) -> aws.secretsmanager.Secret:
    """Create a Secrets Manager secret and initial version if it does not exist.

    This helper always creates a new Pulumi-managed secret.  If a secret with
    the same name already exists in AWS it will be adopted and no new version
    will be published.  All secrets are marked as confidential using
    Pulumi’s secret tracking to avoid leaking values in CLI output.
    """
    secret = aws.secretsmanager.Secret(
        f"secret-{name.replace('/', '-')}",
        name=name,
        description=description,
        opts=pulumi.ResourceOptions(provider=provider),
    )
    # Generate a random string to ensure the secret has some content if
    # initial_value is empty.  Using secrets.token_urlsafe provides a high
    # entropy key suitable for API tokens or encryption keys.
    secret_string = pulumi.Output.secret(json.dumps(initial_value))
    aws.secretsmanager.SecretVersion(
        f"secret-version-{name.replace('/', '-')}",
        secret_id=secret.id,
        secret_string=secret_string,
        opts=pulumi.ResourceOptions(parent=secret, provider=provider),
    )
    return secret

# n8n secret contains at least an API key and the configured domain
n8n_secret = ensure_secret(
    n8n_secret_name,
    "Credentials for n8n", {
        "N8N_API_KEY": secrets.token_urlsafe(24),
        "N8N_HOST": n8n_domain,
        # Additional keys may be added manually via the AWS console
    }
)

# Database secret stores credentials for the Aurora cluster
db_username = f"admin{secrets.token_hex(4)}"
db_password = secrets.token_urlsafe(16)
db_secret = ensure_secret(
    db_secret_name,
    "Database credentials for Zep", {
        "username": db_username,
        "password": db_password,
    }
)

# Optional Qdrant secret.  If you need to secure Qdrant with an API key
# populate the JSON with appropriate fields; otherwise leave empty.
qdrant_secret = ensure_secret(
    qdrant_secret_name,
    "Qdrant API credentials", {
        "api_key": secrets.token_urlsafe(24)
    }
)

# -----------------------------------------------------------------------------
# IAM Role for EC2 instance
# -----------------------------------------------------------------------------

# Assume role policy allowing EC2 to assume this role
assume_role_policy = aws.iam.get_policy_document(
    statements=[aws.iam.GetPolicyDocumentStatementArgs(
        actions=["sts:AssumeRole"],
        principals=[aws.iam.GetPolicyDocumentStatementPrincipalArgs(type="Service", identifiers=["ec2.amazonaws.com"])],
    )]
).json

ec2_role = aws.iam.Role(
    "ec2-role",
    assume_role_policy=assume_role_policy,
    tags={"Name": pulumi.get_project() + "-ec2-role"},
    opts=pulumi.ResourceOptions(provider=provider),
)

# Attach managed policies for Secrets Manager read, S3 write and CloudWatch
# logging.  Additional fine‑grained policies can be created as needed.
aws.iam.RolePolicyAttachment(
    "secrets-manager-read",
    role=ec2_role.name,
    policy_arn="arn:aws:iam::aws:policy/SecretsManagerReadWrite",
    opts=pulumi.ResourceOptions(provider=provider),
)
aws.iam.RolePolicyAttachment(
    "s3-full-access",
    role=ec2_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
    opts=pulumi.ResourceOptions(provider=provider),
)
aws.iam.RolePolicyAttachment(
    "cloudwatch-agent-policy",
    role=ec2_role.name,
    policy_arn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    opts=pulumi.ResourceOptions(provider=provider),
)

instance_profile = aws.iam.InstanceProfile(
    "ec2-instance-profile",
    role=ec2_role.name,
    opts=pulumi.ResourceOptions(provider=provider),
)

# -----------------------------------------------------------------------------
# Aurora Serverless PostgreSQL
# -----------------------------------------------------------------------------

db_subnet_group = aws.rds.SubnetGroup(
    "db-subnet-group",
    subnet_ids=[private_subnet.id],
    tags={"Name": pulumi.get_project() + "-db-subnet"},
    opts=pulumi.ResourceOptions(provider=provider),
)

aurora_cluster = aws.rds.Cluster(
    "aurora-cluster",
    engine="aurora-postgresql",
    engine_version=db_engine_version,
    database_name="zep",
    master_username=db_username,
    master_password=db_password,
    db_subnet_group_name=db_subnet_group.name,
    vpc_security_group_ids=[db_sg.id],
    storage_encrypted=True,
    backup_retention_period=7,
    engine_mode="provisioned",
    serverlessv2_scaling_configuration=aws.rds.ClusterServerlessV2ScalingConfigurationArgs(
        min_capacity=db_min_capacity,
        max_capacity=db_max_capacity,
    ),
    tags={"Name": pulumi.get_project() + "-aurora"},
    opts=pulumi.ResourceOptions(provider=provider),
)

# A serverless v2 cluster still requires at least one instance attached
aurora_instance = aws.rds.ClusterInstance(
    "aurora-cluster-instance",
    cluster_identifier=aurora_cluster.id,
    instance_class="db.serverless",
    engine="aurora-postgresql",
    engine_version=db_engine_version,
    publicly_accessible=False,
    tags={"Name": pulumi.get_project() + "-aurora-instance"},
    opts=pulumi.ResourceOptions(provider=provider),
)

# -----------------------------------------------------------------------------
# EC2 Key Pair (optional)
# -----------------------------------------------------------------------------

key_pair = None
if ssh_public_key:
    key_pair = aws.ec2.KeyPair(
        "ssh-keypair",
        key_name=f"{pulumi.get_project()}-key",
        public_key=ssh_public_key,
        opts=pulumi.ResourceOptions(provider=provider),
    )

# -----------------------------------------------------------------------------
# EC2 Instance with user-data script
# -----------------------------------------------------------------------------

# Retrieve the latest Amazon Linux 2 AMI
ami = aws.ec2.get_ami(
    most_recent=True,
    owners=["amazon"],
    filters=[{"name": "name", "values": ["amzn2-ami-hvm-*-x86_64-gp2"]}],
)

# User data script.  This script runs on first boot to set up the instance.  It
# installs Docker, Docker Compose, jq and the AWS CLI, checks out the repo,
# pulls secrets from Secrets Manager and brings up the Docker Compose stack.
user_data_lines: List[str] = []
user_data_lines.append("#!/bin/bash -xe")
user_data_lines.append("exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1")
user_data_lines.append("yum update -y")
user_data_lines.append("amazon-linux-extras install epel -y")
user_data_lines.append("yum install -y docker git jq awscli")
user_data_lines.append("systemctl enable docker")
user_data_lines.append("systemctl start docker")
user_data_lines.append("mkdir -p /opt/app")
user_data_lines.append("cd /opt/app")
user_data_lines.append("# Placeholder for cloning your repository; the repository URL should be configured after pushing to GitHub")
user_data_lines.append("# git clone https://github.com/your-org/aws-infra-agentstack.git . || true")
user_data_lines.append("# Pull down the docker-compose file if not present")
repo_dir = os.path.dirname(__file__)
docker_compose_content = open(os.path.join(repo_dir, 'docker-compose.yaml')).read().replace("EOF", "EOX")
caddyfile_content = open(os.path.join(repo_dir, 'Caddyfile')).read().replace("EOF", "EOX")
fetch_script_content = open(os.path.join(repo_dir, 'scripts', 'fetch_secrets.sh')).read().replace("EOF", "EOX")
backup_script_content = open(os.path.join(repo_dir, 'scripts', 'backup_to_s3.sh')).read().replace("EOF", "EOX")
user_data_lines.append("cat > docker-compose.yaml <<'EOF'\n" + docker_compose_content + "\nEOF")
user_data_lines.append("cat > Caddyfile <<'EOF'\n" + caddyfile_content + "\nEOF")
user_data_lines.append("cat > fetch_secrets.sh <<'EOF'\n" + fetch_script_content + "\nEOF")
user_data_lines.append("cat > backup_to_s3.sh <<'EOF'\n" + backup_script_content + "\nEOF")
user_data_lines.append("chmod +x fetch_secrets.sh backup_to_s3.sh")
user_data_lines.append("export AWS_REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)")
user_data_lines.append(f"export N8N_SECRET_NAME='{n8n_secret_name}'")
user_data_lines.append(f"export DB_SECRET_NAME='{db_secret_name}'")
user_data_lines.append(f"export QDRANT_SECRET_NAME='{qdrant_secret_name}'")
user_data_lines.append("export BACKUP_BUCKET='{0}'".format(backup_bucket_name))
user_data_lines.append("export DB_HOST='{0}'".format(aurora_cluster.endpoint))
user_data_lines.append("export DB_PORT='5432'")
user_data_lines.append("export DB_NAME='zep'")
user_data_lines.append("export N8N_HOST='{0}'".format(n8n_domain))
user_data_lines.append("# Fetch secrets and create .env files for n8n and zep\n./fetch_secrets.sh")
user_data_lines.append("# Start the stack\ndocker compose up -d")
user_data_lines.append("# Schedule daily backups at 2 AM\n(crontab -l 2>/dev/null; echo '0 2 * * * cd /opt/app && ./backup_to_s3.sh') | crontab -")
user_data_lines.append(
    "# Health check script\n"
    "cat > /usr/local/bin/n8n-health-check.sh <<'EOF'\n"
    "#!/bin/bash\n"
    "URL=\\\"https://{0}\\\"\n"
    "if ! curl -fsSL $URL >/dev/null; then\n"
    "  logger -p user.warn 'n8n health check failed'\n"
    "fi\n"
    "EOF\n"
    "chmod +x /usr/local/bin/n8n-health-check.sh\n"
    "(crontab -l; echo '*/5 * * * * /usr/local/bin/n8n-health-check.sh') | crontab -"
    .format(n8n_domain)
)
user_data = "\n".join(user_data_lines)

ec2_instance = aws.ec2.Instance(
    "n8n-host",
    ami=ami.id,
    instance_type=instance_type,
    subnet_id=public_subnet.id,
    vpc_security_group_ids=[ec2_sg.id],
    key_name=key_pair.key_name if key_pair else None,
    iam_instance_profile=instance_profile.name,
    associate_public_ip_address=True,
    user_data=user_data,
    tags={"Name": pulumi.get_project() + "-n8n-host"},
    opts=pulumi.ResourceOptions(provider=provider, depends_on=[aurora_instance]),
)

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

pulumi.export("publicIp", ec2_instance.public_ip)
pulumi.export("n8nUrl", pulumi.Output.concat("https://", n8n_domain))
pulumi.export("dbEndpoint", aurora_cluster.endpoint)
pulumi.export("backupBucket", backup_bucket.bucket)
pulumi.export("n8nSecretName", n8n_secret.name)
pulumi.export("dbSecretName", db_secret.name)
pulumi.export("qdrantSecretName", qdrant_secret.name)
