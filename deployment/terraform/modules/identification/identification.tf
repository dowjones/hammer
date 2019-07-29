resource "aws_cloudformation_stack" "identification" {
    name = "hammer-identification-main"
    depends_on = [
                  "aws_s3_bucket_object.identification-cfn",
                  "aws_s3_bucket_object.identification-nested-cfn",
                  "aws_s3_bucket_object.logs-forwarder",
                  "aws_s3_bucket_object.ddb-tables-backup",
                  "aws_s3_bucket_object.sg-issues-identification",
                  "aws_s3_bucket_object.s3-acl-issues-identification",
                  "aws_s3_bucket_object.s3-policy-issues-identification",
                  "aws_s3_bucket_object.iam-keyrotation-issues-identification",
                  "aws_s3_bucket_object.iam-user-inactive-keys-identification",
                  "aws_s3_bucket_object.cloudtrails-issues-identification",
                  "aws_s3_bucket_object.ebs-unencrypted-volume-identification",
                  "aws_s3_bucket_object.ebs-public-snapshots-identification",
                  "aws_s3_bucket_object.ami-public-access-issues-identification",
                  "aws_s3_bucket_object.sqs-public-policy-identification",
                  "aws_s3_bucket_object.s3-unencrypted-bucket-issues-identification",
                  "aws_s3_bucket_object.rds-unencrypted-instance-identification",
                  "aws_s3_bucket_object.ecs-privileged-access-issues-identification",
                  "aws_s3_bucket_object.ecs-logging-issues-identification",
                  "aws_s3_bucket_object.ecs-external-image-source-issues-identification",
                  "aws_s3_bucket_object.redshift-audit-logging-issues-identification",
                  "aws_s3_bucket_object.redshift-unencrypted-cluster-identification",
                  "aws_s3_bucket_object.redshift-cluster-public-access-identification",
                  "aws_s3_bucket_object.elasticsearch-domain-logging-issues-identification",
                  "aws_s3_bucket_object.elasticsearch-unencrypted-domain-identification",
                  "aws_s3_bucket_object.elasticsearch-public-access-domain-identification"
                 ]

    tags = "${var.tags}"

    parameters {
        SourceS3Bucket  = "${var.s3bucket}"
        NestedStackTemplate = "https://${var.s3bucket}.s3.amazonaws.com/${aws_s3_bucket_object.identification-nested-cfn.id}"
        ResourcesPrefix = "${var.resources-prefix}"
        IdentificationIAMRole = "${var.identificationIAMRole}"
        IdentificationCheckRateExpression = "${var.identificationCheckRateExpression}"
        LambdaSubnets = "${var.lambdaSubnets}"
        LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
        SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}",
        SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}",
        SourceIdentificationSG = "${aws_s3_bucket_object.sg-issues-identification.id}"
        SourceIdentificationS3ACL = "${aws_s3_bucket_object.s3-acl-issues-identification.id}"
        SourceIdentificationS3Policy = "${aws_s3_bucket_object.s3-policy-issues-identification.id}"
        SourceIdentificationIAMUserKeysRotation = "${aws_s3_bucket_object.iam-keyrotation-issues-identification.id}"
        SourceIdentificationIAMUserInactiveKeys = "${aws_s3_bucket_object.iam-user-inactive-keys-identification.id}"
        SourceIdentificationCloudTrails = "${aws_s3_bucket_object.cloudtrails-issues-identification.id}"
        SourceIdentificationEBSVolumes = "${aws_s3_bucket_object.ebs-unencrypted-volume-identification.id}"
        SourceIdentificationEBSSnapshots = "${aws_s3_bucket_object.ebs-public-snapshots-identification.id}"
        SourceIdentificationRDSSnapshots = "${aws_s3_bucket_object.rds-public-snapshots-identification.id}"
        SourceIdentificationAMIPublicAccess = "${aws_s3_bucket_object.ami-public-access-issues-identification.id}"
        SourceIdentificationSQSPublicPolicy = "${aws_s3_bucket_object.sqs-public-policy-identification.id}"
        SourceIdentificationS3Encryption = "${aws_s3_bucket_object.s3-unencrypted-bucket-issues-identification.id}"
        SourceIdentificationRDSEncryption = "${aws_s3_bucket_object.rds-unencrypted-instance-identification.id}"
        SourceIdentificationECSPrivilegedAccess = "${aws_s3_bucket_object.ecs-privileged-access-issues-identification.id}"
        SourceIdentificationECSLogging = "${aws_s3_bucket_object.ecs-logging-issues-identification.id}"
        SourceIdentificationECSExternalImageSource = "${aws_s3_bucket_object.ecs-external-image-source-issues-identification.id}"
        SourceIdentificationRedshiftLogging = "${aws_s3_bucket_object.redshift-audit-logging-issues-identification.id}"
        SourceIdentificationRedshiftClusterEncryption = "${aws_s3_bucket_object.redshift-unencrypted-cluster-identification.id}"
        SourceIdentificationRedshiftPublicAccess = "${aws_s3_bucket_object.redshift-cluster-public-access-identification.id}"
        SourceIdentificationElasticSearchLogging = "${aws_s3_bucket_object.elasticsearch-domain-logging-issues-identification.id}"      
        SourceIdentificationElasticSearchEncryption = "${aws_s3_bucket_object.elasticsearch-unencrypted-domain-identification.id}"
        SourceIdentificationElasticSearchPublicAccess = "${aws_s3_bucket_object.elasticsearch-public-access-domain-identification.id}"
    }
    template_url = "https://${var.s3bucket}.s3.amazonaws.com/${aws_s3_bucket_object.identification-cfn.id}"
}