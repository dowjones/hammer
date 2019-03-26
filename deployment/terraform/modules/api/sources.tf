resource "aws_s3_bucket_object" "api-cfn" {
    bucket = "${var.s3bucket}"
    key    = "cfn/${format("identification-%s.json", "${md5(file("${path.module}/../../../cf-templates/api.json"))}")}"
    source = "${path.module}/../../../cf-templates/api.json"
}

resource "aws_s3_bucket_object" "api" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("api-%s.zip", "${md5(file("${path.module}/../../../packages/api.zip"))}")}"
    source = "${path.module}/../../../packages/api.zip"
}