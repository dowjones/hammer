resource "aws_s3_bucket_object" "identification-role-cfn" {
    bucket = "${var.s3bucket}"
    key    = "cfn/${format("identification-role-%s.json", "${md5(file("${path.module}/../../../cf-templates/identification-role.json"))}")}"
    source = "${path.module}/../../../cf-templates/identification-role.json"
}

resource "aws_s3_bucket_object" "reporting-remediation-role-cfn" {
    bucket = "${var.s3bucket}"
    key    = "cfn/${format("reporting-remediation-role-%s.json", "${md5(file("${path.module}/../../../cf-templates/reporting-remediation-role.json"))}")}"
    source = "${path.module}/../../../cf-templates/reporting-remediation-role.json"
}
