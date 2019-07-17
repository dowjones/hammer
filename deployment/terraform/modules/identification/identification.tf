data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_lambda_function" "lambda-logs-forwarder" {
  depends_on = [
    aws_cloudwatch_log_group.log-group-lambda-evaluate
  ]
  function_name = "${var.resources-prefix}logs-forwarder"

  s3_bucket = "${var.s3bucket}"
  s3_key    = "${aws_s3_bucket_object.logs-forwarder.id}"

  description = "Lambda function for parsing logs"
  role    = "${var.identificationIAMRole}"
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

  s3_bucket = "${var.s3bucket}"
  s3_key    = "${aws_s3_bucket_object.logs-forwarder.id}"

  description = "Lambda function for parsing logs"
  role    = "${var.identificationIAMRole}"
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
  destination_arn = aws_lambda_function.lambda-logs-forwarder.arn
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
    principal = "logs.${data.aws_region.current.name}.amazonaws.com"
    source_arn = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"

}aws_region

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




module "hammer_id_nested_sg" {

    depends_on
    source    = "identification_nested_template.tf"
    tags = "${var.tags}"
    parameters {
        ResourcesPrefix = "${var.resources-prefix}"
        IdentificationIAMRole = "${var.identificationIAMRole}"
        IdentificationCheckRateExpression = "${var.identificationCheckRateExpression}"
        LambdaSubnets = "${var.lambdaSubnets}"
        LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
        SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}",
        SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}",
        IdentificationLambdaSource = "${aws_s3_bucket_object.sg-issues-identification.id}"
        InitiateLambdaName = ${var.initiateSecurityGroupLambdaFunctionName}
        SourceS3Bucket = "${var.s3bucket}"
        InitiateLambdaDescription = "Lambda function for initiate to identify bad security groups"
        InitiateLambdaHandler = "initiate_to_desc_sec_grps.lambda_handler"
        SourceIdentificationSG =  "${aws_s3_bucket_object.sg-issues-identification.id}"
        LambdaLogsForwarderArn =  aws_lambda_function.lambda-logs-forwarder.arn
        EvaluateLambdaName = ${var.identifySecurityGroupLambdaFunctionName}
        EvaluateLambdaDescription = "Lambda function to describe security groups unrestricted access."
        EvaluateLambdaHandler = "describe_sec_grps_unrestricted_access.lambda_handler"
        EvaluateLambdaMemorySize = 512
        EventRuleName = ${var.resources-prefix}SourceIdentificationSG
        EventRuleDescription = "Hammer ScheduledRule to initiate Security Groups evaluations"
        SNSDisplayName = ${var.resources-prefix}${var.snsDisplayNameSecurityGroups}
        SNSTopicName = ${var.resources-prefix}${var.snsTopicNameSecurityGroups}
        SNSIdentificationErrors = aws_sns_topic.sns-identification-errors.name
    }
}
