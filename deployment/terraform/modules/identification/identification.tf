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
                  "aws_s3_bucket_object.rds-unencrypted-instance-identification"
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
    }

    template_url = "https://${var.s3bucket}.s3.amazonaws.com/${aws_s3_bucket_object.identification-cfn.id}"
}