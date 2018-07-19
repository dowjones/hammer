resource "aws_s3_bucket_object" "ddb-cfn" {
    bucket = "${var.s3bucket}"
    key    = "cfn/${format("ddb-%s.json", "${md5(file("${path.module}/../../../cf-templates/ddb.json"))}")}"
    source = "${path.module}/../../../cf-templates/ddb.json"
}