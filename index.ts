import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

const config = new pulumi.Config();
// AWS region from configuration or default region
const region = config.get("aws:region") || aws.config.region;
// Optional domain name used for TLS certificates.  You must own this domain
// and configure DNS records (A/AAAA) to point to the EC2 instance's public IP.
const domainName = config.get("domainName");

// Names for secrets stored in Secrets Manager.  These can be overridden in
// stack configuration.  The secrets must exist prior to deployment.
const n8nSecretName = config.get("n8n:secretName") || "n8n/credentials";
const qdrantSecretName = config.get("qdrant:secretName") || "qdrant/credentials";
const auroraMasterUsername = config.get("aurora:masterUsername") || "dbadmin";
const auroraMasterPassword = config.requireSecret("aurora:masterPassword");

// Capture project and stack names for use in user-data scripts
const projectName = pulumi.getProject();

// -----------------------------------------------------------------------------
// VPC and Networking
// -----------------------------------------------------------------------------

// Use AWSX to create a VPC with public and private subnets across two
// availability zones.  A NAT gateway is automatically provisioned for
// outbound internet access from the private subnets.
const vpc = new awsx.ec2.Vpc("app-vpc", {
    cidrBlock: "10.0.0.0/16",
    numberOfAvailabilityZones: 2,
    natGateways: { strategy: "Single" },
    tags: { Name: `${pulumi.getProject()}-vpc` },
});

// Export subnet IDs for reference
const publicSubnetIds = vpc.publicSubnetIds;
const privateSubnetIds = vpc.privateSubnetIds;

// -----------------------------------------------------------------------------
// Security Groups
// -----------------------------------------------------------------------------

// Security group for the EC2 host.  Allows inbound SSH (22), HTTP (80) and
// HTTPS (443) from anywhere, and all traffic from the VPC CIDR.  Egress is
// unrestricted.
const ec2Sg = new aws.ec2.SecurityGroup("ec2-sg", {
    vpcId: vpc.vpcId,
    description: "Allow SSH, HTTP and HTTPS inbound; unrestricted egress",
    ingress: [
        { protocol: "tcp", fromPort: 22, toPort: 22, cidrBlocks: ["0.0.0.0/0"] },
        { protocol: "tcp", fromPort: 80, toPort: 80, cidrBlocks: ["0.0.0.0/0"] },
        { protocol: "tcp", fromPort: 443, toPort: 443, cidrBlocks: ["0.0.0.0/0"] },
        { protocol: "tcp", fromPort: 0, toPort: 65535, cidrBlocks: [vpc.vpc.cidrBlock] },
    ],
    egress: [ { protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] } ],
    tags: { Name: "ec2-sg" },
});

// Security group for the database allowing connections from the EC2 instances.
const dbSg = new aws.ec2.SecurityGroup("db-sg", {
    vpcId: vpc.vpcId,
    description: "Allow PostgreSQL traffic from EC2",
    ingress: [
        { protocol: "tcp", fromPort: 5432, toPort: 5432, securityGroups: [ec2Sg.id] },
    ],
    egress: [ { protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] } ],
    tags: { Name: "db-sg" },
});

// -----------------------------------------------------------------------------
// Secrets Manager Secrets
// -----------------------------------------------------------------------------

function ensureSecret(secretName: string): aws.secretsmanager.Secret {
    return new aws.secretsmanager.Secret(secretName.replace(/\//g, "-"), {
        name: secretName,
    });
}

const n8nSecret = ensureSecret(n8nSecretName);
const qdrantSecret = ensureSecret(qdrantSecretName);
// Create a secret for the Aurora master password.  The value will be set from
// configuration.
const auroraPasswordSecret = new aws.secretsmanager.Secret("aurora-master-password", {
    name: `${pulumi.getProject()}/aurora/masterPassword`,
});
new aws.secretsmanager.SecretVersion("aurora-master-password-version", {
    secretId: auroraPasswordSecret.id,
    secretString: auroraMasterPassword,
});

// -----------------------------------------------------------------------------
// Aurora Serverless v2 PostgreSQL Cluster
// -----------------------------------------------------------------------------

// Create a subnet group for the database using the private subnets
const dbSubnetGroup = new aws.rds.SubnetGroup("db-subnet-group", {
    subnetIds: privateSubnetIds,
    tags: { Name: "app-db-subnet-group" },
});

// Create the cluster with serverless v2 scaling configuration.  Engine mode
// 'provisioned' is required for serverless v2 as of this writing.
const dbCluster = new aws.rds.Cluster("aurora-cluster", {
    clusterIdentifier: "app-aurora-cluster",
    engine: "aurora-postgresql",
    engineMode: "provisioned",
    engineVersion: "13.6",
    databaseName: "appdb",
    masterUsername: auroraMasterUsername,
    masterPassword: auroraMasterPassword,
    dbSubnetGroupName: dbSubnetGroup.name,
    vpcSecurityGroupIds: [dbSg.id],
    storageEncrypted: true,
    serverlessv2ScalingConfiguration: {
        minCapacity: 0.5,
        maxCapacity: 4.0,
        secondsUntilAutoPause: 3600,
    },
    tags: { Name: "app-aurora-cluster" },
});

// Create a serverless instance in the cluster
const dbInstance = new aws.rds.ClusterInstance("aurora-instance", {
    clusterIdentifier: dbCluster.id,
    instanceClass: "db.serverless",
    engine: "aurora-postgresql",
    engineVersion: "13.6",
    publiclyAccessible: false,
    tags: { Name: "app-aurora-instance" },
});

// -----------------------------------------------------------------------------
// S3 Bucket for backups
// -----------------------------------------------------------------------------

const backupBucket = new aws.s3.Bucket("backup-bucket", {
    bucket: pulumi.interpolate`${pulumi.getProject()}-backup-${pulumi.getStack()}`,
    versioning: { enabled: true },
    serverSideEncryptionConfiguration: {
        rule: {
            applyServerSideEncryptionByDefault: { sseAlgorithm: "AES256" },
        },
    },
    tags: { Name: "app-backup-bucket" },
});

// -----------------------------------------------------------------------------
// IAM Role and Instance Profile
// -----------------------------------------------------------------------------

// Assume role policy for EC2
const assumeRolePolicy = {
    Version: "2012-10-17",
    Statement: [
        {
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Principal: { Service: "ec2.amazonaws.com" },
        },
    ],
};

const ec2Role = new aws.iam.Role("ec2-role", {
    assumeRolePolicy: JSON.stringify(assumeRolePolicy),
});

// Policy granting the EC2 instance permissions to read secrets and write to
// the backup bucket, and to emit logs to CloudWatch.
const ec2RolePolicy = new aws.iam.RolePolicy("ec2-role-policy", {
    role: ec2Role.id,
    policy: pulumi.all([backupBucket.arn, n8nSecret.arn, qdrantSecret.arn, auroraPasswordSecret.arn]).apply(
        ([bucketArn, n8nArn, qdrantArn, auroraArn]) =>
            JSON.stringify({
                Version: "2012-10-17",
                Statement: [
                    {
                        Effect: "Allow",
                        Action: ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                        Resource: [n8nArn, qdrantArn, auroraArn],
                    },
                    {
                        Effect: "Allow",
                        Action: ["s3:PutObject", "s3:PutObjectAcl", "s3:GetObject"],
                        Resource: [`${bucketArn}/*`],
                    },
                    {
                        Effect: "Allow",
                        Action: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        Resource: "arn:aws:logs:*:*:*",
                    },
                ],
            }),
    ),
});

const instanceProfile = new aws.iam.InstanceProfile("ec2-instance-profile", {
    role: ec2Role.name,
});

// -----------------------------------------------------------------------------
// EC2 Instance with Docker Compose
// -----------------------------------------------------------------------------

// Fetch the latest Amazon Linux 2 AMI (x86_64)
const ami = aws.ec2.getAmi({
    mostRecent: true,
    owners: ["amazon"],
    filters: [
        { name: "name", values: ["amzn2-ami-hvm-*-x86_64-gp2"] },
    ],
});

// Build the user-data script.  We use a template literal to embed values from
// Pulumi configuration (secret names, DB endpoint, bucket, domain).  Curly
// braces within the script that shouldn't be interpreted by TypeScript must
// be escaped with double braces.
const userData = pulumi.all([dbCluster.endpoint, auroraMasterUsername, backupBucket.bucket, n8nSecretName, qdrantSecretName]).apply(
    ([dbEndpoint, dbUser, backupBucketName, n8nSecret, qdrantSecret]) => {
        return `#!/bin/bash
set -eu
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

# Install updates and Docker
yum update -y
yum install -y docker
yum install -y aws-cli
systemctl start docker
usermod -a -G docker ec2-user

# Install docker-compose
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Create working directory
mkdir -p /opt/app

# Retrieve secrets from Secrets Manager
n8n_creds=$(aws secretsmanager get-secret-value --secret-id ${n8nSecret} --query SecretString --output text || echo "{{}}")
qdrant_creds=$(aws secretsmanager get-secret-value --secret-id ${qdrantSecret} --query SecretString --output text || echo "{{}}")
aurora_pass=$(aws secretsmanager get-secret-value --secret-id ${projectName}/aurora/masterPassword --query SecretString --output text || echo "")

# Write environment file for services
cat > /opt/app/.env <<EOF
N8N_CREDENTIALS=$n8n_creds
QDRANT_CREDENTIALS=$qdrant_creds
POSTGRES_PASSWORD=$aurora_pass
POSTGRES_HOST=${dbEndpoint}
POSTGRES_PORT=5432
POSTGRES_USER=${dbUser}
EOF

# Write docker-compose file including Caddy as a reverse proxy
cat > /opt/app/docker-compose.yml <<'EOF'
version: "3.8"
services:
  caddy:
    image: caddy:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    environment:
      - DOMAIN_NAME=${domainName || ''}
    volumes:
      - caddy_data:/data
      - caddy_config:/config
      - ./Caddyfile:/etc/caddy/Caddyfile
    networks:
      - web
  n8n:
    image: n8nio/n8n:latest
    restart: always
    env_file:
      - /opt/app/.env
    ports:
      - "5678:5678"
    volumes:
      - n8n-data:/home/node/.n8n
    networks:
      - web
  zep:
    image: ghcr.io/getzep/zep:latest
    restart: always
    env_file:
      - /opt/app/.env
    ports:
      - "8000:8000"
    networks:
      - web
  qdrant:
    image: qdrant/qdrant:latest
    restart: always
    ports:
      - "6333:6333"
    volumes:
      - qdrant-data:/qdrant/storage
    networks:
      - web

volumes:
  caddy_data:
  caddy_config:
  n8n-data:
  qdrant-data:

networks:
  web:
EOF

# Write Caddyfile for reverse proxy with TLS
cat > /opt/app/Caddyfile <<EOF
${domainName || ''} {
    encode gzip
    reverse_proxy /n8n/* n8n:5678
    reverse_proxy /zep/* zep:8000
    reverse_proxy /qdrant/* qdrant:6333
    ${domainName ? 'tls email@example.com' : '# tls disabled because no domainName provided'}
}
EOF

cd /opt/app
/usr/local/bin/docker-compose up -d

# Export backup bucket name for the backup script
BACKUP_BUCKET_NAME=${backupBucketName}

# Backup script to sync Docker volumes to S3 daily
cat > /opt/app/backup.sh <<'BCK'
#!/bin/bash
set -euo pipefail
export PATH=$PATH:/usr/local/bin
if [ -d /var/lib/docker/volumes/n8n-data/_data ]; then
  aws s3 sync /var/lib/docker/volumes/n8n-data/_data s3://$BACKUP_BUCKET_NAME/n8n-backups/ --delete
fi
if [ -d /var/lib/docker/volumes/qdrant-data/_data ]; then
  aws s3 sync /var/lib/docker/volumes/qdrant-data/_data s3://$BACKUP_BUCKET_NAME/qdrant-backups/ --delete
fi
BCK
chmod +x /opt/app/backup.sh

# Schedule daily backups at 03:30 UTC
echo "30 3 * * * root /opt/app/backup.sh >> /var/log/backup.log 2>&1" >> /etc/crontab

`;
    }
);

const ec2Instance = new aws.ec2.Instance("app-instance", {
    instanceType: "t3.small",
    ami: ami.then(a => a.id),
    iamInstanceProfile: instanceProfile.name,
    vpcSecurityGroupIds: [ec2Sg.id],
    subnetId: vpc.publicSubnetIds[0],
    associatePublicIpAddress: true,
    userData: userData,
    tags: { Name: "app-instance" },
});

// -----------------------------------------------------------------------------
// Outputs
// -----------------------------------------------------------------------------

export const vpcId = vpc.vpcId;
export const publicSubnetsOut = publicSubnetIds;
export const privateSubnetsOut = privateSubnetIds;
export const ec2PublicIp = ec2Instance.publicIp;
export const auroraEndpoint = dbCluster.endpoint;
export const backupBucketName = backupBucket.id;