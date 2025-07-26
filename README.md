# AWS Infrastructure for n8n, Zep, Qdrant & Aurora

This repository contains a Pulumi program written in **TypeScript** that provisions a
production‑ready AWS environment for running the following services:

* **n8n** – a workflow automation tool that runs publicly over HTTPS.
* **Zep** – a long‑term memory store for large language models.
* **Qdrant** – a high‑performance vector database used by Zep.
* **Aurora Serverless v2** – a PostgreSQL database used by Zep for
  metadata storage.
* **AWS Secrets Manager** – for storing credentials such as n8n API keys,
  Qdrant tokens and the Aurora master password.
* **S3 Backup Bucket** – versioned and encrypted, used to store
  backups of Docker volumes on the EC2 instance.

In addition to the core services, the program creates a dedicated VPC with
public and private subnets, NAT gateways, security groups, IAM roles, an EC2
instance to run Docker Compose, and a scheduled backup job.  The EC2
instance installs Docker and Docker Compose on boot, fetches secrets from
Secrets Manager and starts the containers using a generated `docker‑compose.yml`.

## Repository Structure

```
aws-infra-agentstack/
├── Pulumi.yaml           # Pulumi project definition
├── Pulumi.dev.yaml       # Default stack configuration (region, secrets, domain)
├── package.json          # Node dependencies for Pulumi and AWS SDK
├── tsconfig.json         # TypeScript compiler options
├── index.ts              # Pulumi program entry point (TypeScript)
├── docker-compose.yaml   # Reference compose file for local development
├── Caddyfile             # Example Caddy reverse proxy configuration
├── scripts/
│   └── getSecrets.ts     # Helper to fetch Secrets Manager secrets
└── .github/workflows/deploy.yml   # GitHub Actions workflow for deployment
```

The root of the repository also includes a `.github/workflows/deploy.yml` file
to demonstrate how you might set up a CI/CD pipeline using GitHub Actions to
deploy this stack.

## Prerequisites

* [Pulumi CLI](https://www.pulumi.com/docs/get-started/install/) `v3.x`
* [Node.js](https://nodejs.org/) 18+ (LTS)
* [AWS CLI](https://aws.amazon.com/cli/) configured with credentials that
  have permission to create the resources defined in this stack
* A Pulumi backend (e.g. pulumi.com) for storing state

## Bootstrapping a New Stack

Clone this repository and `cd` into the `aws-infra-agentstack` directory.  The
instructions below assume you are deploying a stack named `dev`.

```bash
# Install Node dependencies
npm install

# Log into Pulumi backend (if you haven't already)
pulumi login

# Initialise the `dev` stack
pulumi stack init dev

# Configure your AWS region (defaults to us‑east‑2) and secrets.  You can
# adjust these keys as needed.  Use --secret when setting sensitive values.
pulumi config set aws:region us-east-2
pulumi config set n8n:secretName n8n/credentials
pulumi config set qdrant:secretName qdrant/credentials
pulumi config set aurora:masterUsername dbadmin
pulumi config set aurora:masterPassword S3cr3tP@ssw0rd --secret
# Optionally specify a domain name for TLS (must point to the EC2 IP)
pulumi config set domainName example.com

# Preview the resources that will be created
pulumi preview

# Deploy the infrastructure (will prompt for confirmation)
pulumi up

# After the update completes, Pulumi will output values such as the EC2
# public IP and Aurora endpoint.
```

## How It Works

The Pulumi program in `index.ts` performs the following high‑level
actions:

1. **VPC & Networking** – Creates a `/16` VPC with two public and two private
   subnets across availability zones using the AWSX library.  Public subnets
   have an Internet Gateway, and private subnets route outbound traffic via a
   NAT gateway.
2. **Security Groups** – Defines an EC2 security group allowing SSH (22),
   HTTP (80) and HTTPS (443) from the Internet and all intra‑VPC traffic,
   and a database security group allowing PostgreSQL traffic from the EC2
   group.
3. **Secrets** – Ensures secrets exist in Secrets Manager for n8n and
   Qdrant credentials and creates a new secret for the Aurora master password.
4. **Aurora Cluster** – Provisions an Aurora PostgreSQL Serverless v2
   cluster and a serverless instance in the private subnets with encryption
   and scaling enabled【491621749740767†screenshot】.
5. **S3 Backup Bucket** – Creates a versioned, encrypted S3 bucket for
   storing Docker volume backups.
6. **IAM Role & Instance Profile** – Grants the EC2 instance permission to
   read secrets from Secrets Manager, write backups to S3 and send CloudWatch
   logs.
7. **EC2 Instance** – Launches a `t3.small` Amazon Linux 2 instance in a
   public subnet.  On boot it:
   - Installs Docker and Docker Compose
   - Retrieves secrets from Secrets Manager using the AWS CLI
   - Writes an `.env` file and a `docker‑compose.yml` defining n8n, Zep and
     Qdrant containers
   - Starts the services with `docker-compose up -d`
   - Writes a backup script and schedules it via cron to sync the data
     volumes to the S3 bucket each day at 03:30 UTC
   - **TODO:** Installs and configures a TLS reverse proxy (Caddy or
     NGINX) and sets up CloudWatch monitoring scripts for webhook health

## Managing Secrets

Secrets used by n8n and Qdrant are referenced by name.  Create them in AWS
Secrets Manager prior to deployment.  For example:

```bash
# n8n credentials (e.g. an API key or JSON configuration)
aws secretsmanager create-secret \
  --name n8n/credentials \
  --secret-string '{"N8N_BASIC_AUTH_USER":"admin","N8N_BASIC_AUTH_PASSWORD":"password"}'

# Qdrant credentials (if applicable)
aws secretsmanager create-secret \
  --name qdrant/credentials \
  --secret-string '{"api_key":"your-qdrant-key"}'

```

Pulumi will create a new secret for the Aurora master password automatically,
but you can supply your own value via `pulumi config set aurora:masterPassword
<value> --secret`.

## Local Development with Docker Compose

The `docker-compose.yaml` provided in this repository mirrors the services
started on the EC2 instance.  You can use it locally to develop and test your
workflows:

```bash
cd aws-infra-agentstack
cp .env.example .env  # Create an env file with appropriate values
docker compose up -d
```

This local compose file is not used by Pulumi; the EC2 instance generates
its own `docker-compose.yml` based on the secrets retrieved at runtime.

## CI/CD with GitHub Actions

A sample GitHub Actions workflow is included at `.github/workflows/deploy.yml`.
It installs Pulumi and Node dependencies, logs into your Pulumi backend,
and runs `pulumi preview` and `pulumi up` against the `dev` stack.  You must
provide AWS credentials and a Pulumi access token via repository secrets.

---

This program and associated files provide a baseline for deploying n8n, Zep
and Qdrant on AWS.  Feel free to extend it to add TLS termination,
CloudWatch alarms, webhook gateways or additional stacks for staging and
production.  Contributions and improvements are welcome!