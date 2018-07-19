resource "aws_cloudformation_stack" "identification-role" {
    name = "hammer-identification-master-role"
    depends_on = [
        "aws_s3_bucket_object.identification-role-cfn"
    ]

    capabilities = [ "CAPABILITY_NAMED_IAM" ]

    parameters {
        IdentificationIAMRole = "${var.identificationIAMRole}"
        IdentificationCrossAccountIAMRole = "${var.identificationCrossAccountIAMRole}"
        ResourcesPrefix = "${var.resources-prefix}"
    }

    template_url = "https://${var.s3bucket}.s3.amazonaws.com/${aws_s3_bucket_object.identification-role-cfn.id}"
}

resource "aws_cloudformation_stack" "reporting-remediation-role" {
    name = "hammer-reporting-remediation-ec2-role"
    depends_on = [
        "aws_s3_bucket_object.reporting-remediation-role-cfn"
    ]

    capabilities = [ "CAPABILITY_NAMED_IAM" ]

    parameters {
        SourceS3Bucket = "${var.s3bucket}"
        S3BackupBucket = "${var.s3BackupBucket}"
        ReportingRemediationIAMRole = "${var.reportingRemediationIAMRole}"
        ReportingRemediationIAMCrossAccountRole = "${var.reportingRemediationIAMCrossAccountRole}"
        ResourcesPrefix = "${var.resources-prefix}"
    }

    template_url = "https://${var.s3bucket}.s3.amazonaws.com/${aws_s3_bucket_object.reporting-remediation-role-cfn.id}"
}