
resource "aws_lambda_function" "lambda-logs-forwarder" {
  depends_on = [
    aws_cloudwatch_log_group.log-group-lambda-evaluate
  ]
  function_name = "${var.resources-prefix}logs-forwarder"

  s3_bucket = "${var.SourceS3Bucket}"
  s3_key    = "${var.SourceLogsForwarder}"

  description = "Lambda function for parsing logs"
  role    = "${var.IdentificationIAMRole}"
  handler = "logs_forwarder.lambda_handler"
  runtime = "python3.6"
  timeout          = "300"
  memory_size      = "256"

}

resource "aws_cloudwatch_log_group" "log-group-lambda-evaluate" {
    name = "/aws/lambda/${var.resources-prefix}logs-forwarder"
    retention_in_days = 7
}

resource "aws_lambda_function" "lambda-backup-ddb" {
  depends_on = [
    aws_cloudwatch_log_group.log-group-lambda-backup-ddb
  ]
  function_name = "${var.resources-prefix}backup-ddb"

  s3_bucket = "${var.SourceS3Bucket}"
  s3_key    = "${var.SourceLogsForwarder}"

  description = "Lambda function for parsing logs"
  role    = "${var.IdentificationIAMRole}"
  handler = "ddb_tables_backup.lambda_handler"
  runtime = "python3.6"
  timeout          = "300"
  memory_size      = "256"

}

resource "aws_cloudwatch_log_group" "log-group-lambda-backup-ddb" {
    name = "/aws/lambda/${var.resources-prefix}backup-ddb"
    retention_in_days = 7
}


resource "aws_cloudwatch_log_subscription_filter" "subscription-filter-lambda-backup-ddb" {

  depends_on = [
    aws_cloudwatch_log_group.log-group-lambda-backup-ddb, aws_lambda_permission. ,
    aws_lambda_function.lambda-logs-forwarder
  ]
  log_group_name  = aws_cloudwatch_log_group.log-group-lambda-evaluate.name
  filter_pattern  = "[level != START && level != END && level != DEBUG, ...]"
  destination_arn = "${var.LambdaLogsForwarderArn}"
}

resource "aws_cloudwatch_event_rule" "event-backup-ddb" {

    depends_on = [
      aws_lambda_function.lambda-backup-ddb,
    ]

    name = "${var.resources-prefix}BackupDDB"
    description = "Hammer ScheduledRule for DDB tables backup"
    schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "check-backup-ddb" {
    depends_on = [
      aws_cloudwatch_event_rule.event-backup-ddb,
    ]

    rule = "${aws_cloudwatch_event_rule.event-backup-ddb.name}"
    target_id = "lambda-backup-ddb"
    arn = "${aws_lambda_function.lambda-backup-ddb.arn}"
}

resource "aws_lambda_permission" "allow-cloudwatch-to-call-lambda-logs-forwarder" {
    depends_on = [
      aws_lambda_function.lambda-logs-forwarder
    ]

    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda-logs-forwarder.function_name}"
    principal = "logs.${var.region}.amazonaws.com"
    source_arn = "arn:aws:logs:${var.region}:${var.account_id}:log-group:*"

}

resource "aws_lambda_permission" "allow-cloudwatch-to-call-lambda-backup-ddb" {
    depends_on = [
      aws_lambda_function.lambda-backup-ddb, event-backup-ddb
    ]

    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda-backup-ddb.function_name}"
    principal = "events.amazonaws.com"
    source_arn = "${aws_cloudwatch_event_rule.event-backup-ddb.arn}"

}


resource "aws_sns_topic" "sns-identification-errors" {
  depends_on = [

  name         = "${var.resources-prefix}identification-errors"
}

resource "aws_sns_topic_subscription" "lambda" {
  depends_on = [
      aws_sns_topic.sns-identification-errors, aws_lambda_function.lambda-logs-forwarder
  ]
  topic_arn = "${aws_sns_topic.sns-identification-errors.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.lambda-logs-forwarder.arn}"
}

resource "aws_lambda_permission" "with_sns" {
  depends_on = [
      aws_sns_topic.sns-identification-errors, aws_lambda_function.lambda-logs-forwarder
  ]

  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.lambda-logs-forwarder.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.sns-identification-errors.arn}"
}

resource "aws_cloudwatch_metric_alarm" "alarm-errors-lambda-backup-ddb" {
  depends_on = [
      aws_lambda_function.lambda-backup-ddb, aws_sns_topic.sns-identification-errors,
  ]
  alarm_name          = "/${aws_lambda_function.lambda-backup-ddb.function_name}LambdaError"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "3600"
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"


  alarm_actions = [
    "aws_sns_topic.sns-identification-errors.function_name",
  ]

  ok_actions = [
    "aws_sns_topic.sns-identification-errors.function_name",
  ]

  dimensions {
    FunctionName = "${aws_lambda_function.lambda-backup-ddb.arn}"
  }
}




module "hammer_id_nested" {
    source    = "tf_templates/identiifcation/identification_nested_template.tf"
    tags = "${var.tags}"
    parameters {
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
}


