module "hammer_id_main" {
    source    = "tf_templates/identiifcation/identification_template.tf"
    tags = "${var.tags}"
    parameters {
        SourceS3Bucket  = "${var.s3bucket}"
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

    }
}
