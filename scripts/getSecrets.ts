import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

// Simple helper that fetches a secret value from AWS Secrets Manager and
// prints it to stdout.  Use it during development to inspect secret contents.
//
// Usage: ts-node scripts/getSecrets.ts <secretName> [region]

async function main() {
    const [secretName, region] = process.argv.slice(2);
    if (!secretName) {
        console.error("Usage: getSecrets.ts <secretName> [region]");
        process.exit(1);
    }
    const client = new SecretsManagerClient({ region });
    try {
        const result = await client.send(new GetSecretValueCommand({ SecretId: secretName }));
        const secretString = result.SecretString ?? "";
        try {
            const parsed = JSON.parse(secretString);
            console.log(JSON.stringify(parsed, null, 2));
        } catch {
            console.log(secretString);
        }
    } catch (err) {
        console.error(`Error fetching secret: ${err}`);
        process.exit(1);
    }
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});