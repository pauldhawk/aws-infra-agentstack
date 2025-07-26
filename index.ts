import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
const stack = pulumi.getStack();

// Create a backup S3 bucket with a unique name
const randomSuffix = Math.floor(Math.random() * 1e8).toString(36);
const backupBucket = new aws.s3.Bucket("backup-bucket", {
    bucket: `backup-bucket-${stack}-${randomSuffix}`,
});


