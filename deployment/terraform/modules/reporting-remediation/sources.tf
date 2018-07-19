resource "aws_s3_bucket_object" "reporting-remediation-cfn" {
    bucket = "${var.s3bucket}"
    key    = "cfn/${format("reporting-remediation-%s.json", "${md5(file("${path.module}/../../../cf-templates/reporting-remediation.json"))}")}"
    source = "${path.module}/../../../cf-templates/reporting-remediation.json"
}

resource "aws_s3_bucket_object" "ami-info" {
    bucket = "${var.s3bucket}"
    key    = "ec2/${format("ami-info-%s.zip", "${md5(file("${path.module}/../../../packages/ami-info.zip"))}")}"
    source = "${path.module}/../../../packages/ami-info.zip"
    etag   = "${md5(file("${path.module}/../../../packages/ami-info.zip"))}"
}

resource "aws_s3_bucket_object" "reporting-remediation" {
    bucket = "${var.s3bucket}"
    key    = "ec2/${format("reporting-remediation-%s.zip", "${md5(file("${path.module}/../../../packages/reporting-remediation.zip"))}")}"
    source = "${path.module}/../../../packages/reporting-remediation.zip"
    etag   = "${md5(file("${path.module}/../../../packages/reporting-remediation.zip"))}"
}