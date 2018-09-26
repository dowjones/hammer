resource "aws_s3_bucket_object" "identification-cfn" {
    bucket = "${var.s3bucket}"
    key    = "cfn/${format("identification-%s.json", "${md5(file("${path.module}/../../../cf-templates/identification.json"))}")}"
    source = "${path.module}/../../../cf-templates/identification.json"
}

resource "aws_s3_bucket_object" "logs-forwarder" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("logs-forwarder-%s.zip", "${md5(file("${path.module}/../../../packages/logs-forwarder.zip"))}")}"
    source = "${path.module}/../../../packages/logs-forwarder.zip"
}

resource "aws_s3_bucket_object" "ddb-tables-backup" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("ddb-tables-backup-%s.zip", "${md5(file("${path.module}/../../../packages/ddb-tables-backup.zip"))}")}"
    source = "${path.module}/../../../packages/ddb-tables-backup.zip"
}

resource "aws_s3_bucket_object" "sg-issues-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("sg-issues-identification-%s.zip", "${md5(file("${path.module}/../../../packages/sg-issues-identification.zip"))}")}"
    source = "${path.module}/../../../packages/sg-issues-identification.zip"
}

resource "aws_s3_bucket_object" "s3-acl-issues-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("s3-acl-issues-identificatio-%s.zip", "${md5(file("${path.module}/../../../packages/s3-acl-issues-identification.zip"))}")}"
    source = "${path.module}/../../../packages/s3-acl-issues-identification.zip"
}

resource "aws_s3_bucket_object" "s3-policy-issues-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("s3-policy-issues-identification-%s.zip", "${md5(file("${path.module}/../../../packages/s3-policy-issues-identification.zip"))}")}"
    source = "${path.module}/../../../packages/s3-policy-issues-identification.zip"
}

resource "aws_s3_bucket_object" "iam-keyrotation-issues-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("iam-keyrotation-issues-identification-%s.zip", "${md5(file("${path.module}/../../../packages/iam-keyrotation-issues-identification.zip"))}")}"
    source = "${path.module}/../../../packages/iam-keyrotation-issues-identification.zip"
}

resource "aws_s3_bucket_object" "iam-user-inactive-keys-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("iam-user-inactive-keys-identification-%s.zip", "${md5(file("${path.module}/../../../packages/iam-user-inactive-keys-identification.zip"))}")}"
    source = "${path.module}/../../../packages/iam-user-inactive-keys-identification.zip"
}

resource "aws_s3_bucket_object" "cloudtrails-issues-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("cloudtrails-issues-identification-%s.zip", "${md5(file("${path.module}/../../../packages/cloudtrails-issues-identification.zip"))}")}"
    source = "${path.module}/../../../packages/cloudtrails-issues-identification.zip"
}

resource "aws_s3_bucket_object" "ebs-unencrypted-volume-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("ebs-unencrypted-volume-identification-%s.zip", "${md5(file("${path.module}/../../../packages/ebs-unencrypted-volume-identification.zip"))}")}"
    source = "${path.module}/../../../packages/ebs-unencrypted-volume-identification.zip"
}

resource "aws_s3_bucket_object" "ebs-public-snapshots-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("ebs-public-snapshots-identification-%s.zip", "${md5(file("${path.module}/../../../packages/ebs-public-snapshots-identification.zip"))}")}"
    source = "${path.module}/../../../packages/ebs-public-snapshots-identification.zip"
}

resource "aws_s3_bucket_object" "rds-public-snapshots-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("rds-public-snapshots-identification-%s.zip", "${md5(file("${path.module}/../../../packages/rds-public-snapshots-identification.zip"))}")}"
    source = "${path.module}/../../../packages/rds-public-snapshots-identification.zip"
}

resource "aws_s3_bucket_object" "s3-unencrypted-bucket-issues-identification" {
    bucket = "${var.s3bucket}"
    key    = "lambda/${format("s3-unencrypted-bucket-issues-identification-%s.zip", "${md5(file("${path.module}/../../../packages/s3-unencrypted-bucket-issues-identification.zip"))}")}"
    source = "${path.module}/../../../packages/s3-unencrypted-bucket-issues-identification.zip"
}