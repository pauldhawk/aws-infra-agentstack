# aws‑infra‑agentstack

This repository contains the Pulumi program and associated artefacts required to deploy a production‑ready infrastructure for a self‑hosted [n8n](https://n8n.io/) automation server integrated with the [Zep](https://github.com/getzep/zep) long‑term memory service, [Qdrant](https://qdrant.tech/) vector database and an AWS Aurora Serverless PostgreSQL backend.  The goal is to provide a repeatable, infrastructure‑as‑code template that can be used to stand up a fully functional automation platform on your own AWS account.

## Overview

The stack provisions the following resources:

| Component            | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| **VPC & Networking** | A dedicated VPC with public and private subnets, an Internet gateway and a NAT gateway. |
| **Security groups**  | Fine‑grained firewall rules exposing only ports 80/443 for n8n while permitting intra‑VPC communication. |
| **EC2 instance**     | A single t3.small instance running Amazon Linux 2.  Docker and Docker Compose are installed via cloud‑init. |
| **Docker services**  | Containers for n8n, Zep, Qdrant and Caddy.  Caddy terminates HTTPS via Let’s Encrypt and proxies to the internal services. |
| **Aurora Serverless**| An Aurora PostgreSQL cluster used by Zep for metadata storage.             |
| **Secrets Manager**  | Secrets for n8n API keys, database passwords and optional Qdrant tokens.    |
| **S3 backup**        | A versioned S3 bucket storing daily encrypted backups of all Docker volumes. |
| **Monitoring**        | A simple health‑check script runs every five minutes on the EC2 host and logs failures to CloudWatch. |

## Getting Started

1. **Configure Pulumi**

   Install Pulumi and set up an AWS access method (either via an IAM user key or by assuming a role).  Log in to the Pulumi backend of your choice.  For example, to use a local state file run:

   ```bash
   pulumi login file://~/.pulumi
   ```

2. **Set configuration values**

   Copy `Pulumi.dev.yaml` to a new stack file matching your chosen stack name (e.g. `Pulumi.prod.yaml`) and adjust the configuration keys.  At a minimum you must set `aws:region`, `n8nDomain` and `backupBucketName`.  If you already have Secrets Manager entries for n8n and Zep credentials you should reference their names here; otherwise Pulumi will create new secrets with randomly generated passwords.

3. **Bootstrap the stack**

   Initialize the Python virtual environment and install dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

   Then perform a preview:

   ```bash
   pulumi stack init dev
   pulumi config set aws:region us‑east‑1
   pulumi config set aws‑infra‑agentstack:n8nDomain "n8n.yourdomain.com"
   pulumi preview
   ```

   When satisfied, deploy the stack:

   ```bash
   pulumi up
   ```

4. **DNS record setup**

   After deployment Pulumi will output the public IP address of the EC2 instance.  Create an `A` record in your DNS provider pointing your chosen `n8nDomain` to this IP.  Caddy will automatically request a TLS certificate from Let’s Encrypt once the domain resolves.

5. **Access n8n and Zep**

   Visit `https://<n8nDomain>` in your browser to access the n8n UI.  Zep’s API will be available internally at `http://zep:8000` within the Docker network; you can expose it publicly by adding an additional `reverse_proxy` block to the `Caddyfile` in `docker‑compose.yaml`.

## GitHub Actions

The repository includes a `.github/workflows/deploy.yml` workflow that runs `pulumi preview` and `pulumi up` whenever changes are pushed to the default branch.  The workflow assumes that a Pulumi access token and appropriate AWS credentials are made available via repository secrets or OIDC.  See the comments in that file for configuration details.

## Backup & Monitoring

The EC2 instance installs two cronjobs:

* **Daily backup** – compresses the `n8n_data`, `zep_data` and `qdrant_data` directories, encrypts them (server‑side AES256) and uploads to the specified S3 bucket.
* **Health check** – every five minutes, a script performs a health check against the public n8n endpoint.  Failures are logged to CloudWatch via the system logger.

## Estimated Costs

| Resource                              | Approximate monthly cost*                                 |
|---------------------------------------|-----------------------------------------------------------|
| EC2 t3.small instance                 | ~\$16–\$18 (depending on region and reserved pricing)       |
| Aurora Serverless PostgreSQL (2–4 ACU)| ~\$90–\$110 (pay only for the capacity consumed)            |
| NAT Gateway + data transfer           | ~\$40 (varies with usage)                                  |
| S3 storage for backups                | Negligible at small scale (~\$0.02/GB)                     |
| Secrets Manager (3 secrets)           | ~\$1.50                                                    |

\*Prices are estimates for the `us‑east‑1` region at the time of writing (July 2025) and may vary.  Always consult the [AWS pricing page](https://aws.amazon.com/pricing/) for up‑to‑date information.

## License

This project is provided under the MIT License.  See the `LICENSE` file for details.
