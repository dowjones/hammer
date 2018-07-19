resource "aws_cloudformation_stack" "reporting-remediation" {
    name = "hammer-reporting-remediation"
    depends_on = [
                  "aws_s3_bucket_object.reporting-remediation-cfn",
                  "aws_s3_bucket_object.reporting-remediation"
                 ]

    tags = "${var.tags}"

    capabilities = [ "CAPABILITY_NAMED_IAM" ]

    parameters {
        InstanceType = "${var.ec2InstanceType}"
        ReportingRemediationIAMRole = "${var.reportingRemediationIAMRole}"
        KeyPair = "${var.keyPair}"
        Vpcid = "${var.vpcId}"
        Subnet = "${var.subnet}"
        LambdaLogsForwarderArn = "${var.lambdaLogsForwarderArn}"
        SourceS3Bucket = "${var.s3bucket}"
        SourceAMIInfo = "${aws_s3_bucket_object.ami-info.id}"
        SourceReportingRemediation = "${aws_s3_bucket_object.reporting-remediation.id}"
        ResourcesPrefix = "${var.resources-prefix}"
    }

    template_url = "https://${var.s3bucket}.s3.amazonaws.com/${aws_s3_bucket_object.reporting-remediation-cfn.id}"
}
