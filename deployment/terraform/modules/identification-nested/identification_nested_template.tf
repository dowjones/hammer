resource "aws_lambda_function" "lambda-initiate" {
  depends_on = [
    "aws_cloudwatch_log_group.log-group-lambda-initiate"
  ]
  function_name = "${var.InitiateLambdaName}"

  s3_bucket = "${var.SourceS3Bucket}"
  s3_key    = "${var.SourceIdentification}"

  description = "${var.InitiateLambdaDescription}"
  role    = "${var.IdentificationIAMRole}"
  handler = "${var.InitiateLambdaHandler}"
  runtime = "python3.6"
  timeout          = "300"
  memory_size      = "128"

  environment {
    variables = {
      SNS_ARN = "${aws_sns_topic.sns-notiify-lambda-evaluate.arn}"
    }
  }

}

resource "aws_cloudwatch_log_group" "log-group-lambda-initiate" {
    name = "/aws/lambda/${var.InitiateLambdaName}"
    retention_in_days = 7
}

resource "aws_cloudwatch_log_subscription_filter" "lambda_initiate_logfilter" {

  depends_on = [
    "aws_cloudwatch_log_group.log-group-lambda-initiate"
  ]
  name = "${aws_cloudwatch_log_group.log-group-lambda-initiate.name}"
  log_group_name  = "${aws_cloudwatch_log_group.log-group-lambda-initiate.name}"
  filter_pattern  = "[level != START && level != END && level != DEBUG, ...]"
  destination_arn = "${var.LambdaLogsForwarderArn}"
}

resource "aws_lambda_function" "lambda-evaluate" {
  depends_on = [
    "aws_cloudwatch_log_group.log-group-lambda-evaluate"
  ]
  function_name = "${var.EvaluateLambdaName}"

  s3_bucket = "${var.SourceS3Bucket}"
  s3_key    = "${var.SourceIdentification}"

  description = "${var.EvaluateLambdaDescription}"
  role    = "${var.IdentificationIAMRole}"
  handler = "${var.EvaluateLambdaHandler}"
  runtime = "python3.6"
  timeout          = "300"
  memory_size      = "${var.EvaluateLambdaMemorySize}"

  vpc_config {
      subnet_ids = ["${split(",", var.LambdaSubnets)}"]
      security_group_ids = ["${split(",", var.LambdaSecurityGroups)}"]
  }

}

resource "aws_cloudwatch_log_group" "log-group-lambda-evaluate" {
    name = "/aws/lambda/${var.EvaluateLambdaName}"
    retention_in_days = 7
}

resource "aws_cloudwatch_log_subscription_filter" "lambda_evaluate_logfilter" {

  depends_on = [
    "aws_cloudwatch_log_group.log-group-lambda-evaluate"
  ]
  name = "${aws_cloudwatch_log_group.log-group-lambda-evaluate.name}"
  log_group_name  = "${aws_cloudwatch_log_group.log-group-lambda-evaluate.name}"
  filter_pattern  = "[level != START && level != END && level != DEBUG, ...]"
  destination_arn = "${var.LambdaLogsForwarderArn}"
}

resource "aws_cloudwatch_event_rule" "eventInitiateEvaluation" {

    depends_on = [
      "aws_lambda_function.lambda-initiate"
    ]

    name = "${var.EventRuleName}"
    description = "${var.EventRuleDescription}"
    schedule_expression = "${var.IdentificationCheckRateExpression}"
}

resource "aws_cloudwatch_event_target" "event-initiate-evaluation" {
    depends_on = [
      "aws_cloudwatch_event_rule.eventInitiateEvaluation"
    ]

    rule = "${aws_cloudwatch_event_rule.eventInitiateEvaluation.name}"
    target_id = "lambda-initiate"
    arn = "${aws_lambda_function.lambda-initiate.arn}"
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_initiate_lambda" {
    depends_on = [
      "aws_lambda_function.lambda-initiate" , "aws_cloudwatch_event_rule.eventInitiateEvaluation"
    ]

    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda-initiate.function_name}"
    principal = "events.amazonaws.com"
    source_arn = "${aws_cloudwatch_event_rule.eventInitiateEvaluation.arn}"
}


resource "aws_sns_topic" "sns-notiify-lambda-evaluate" {
  depends_on = [
      "aws_lambda_function.lambda-evaluate"
    ]

  name         = "${var.SNSDisplayName}"
  display_name = "${var.SNSTopicName}"
}

resource "aws_sns_topic_subscription" "lambda" {
  depends_on = [
      "aws_sns_topic.sns-notiify-lambda-evaluate"
  ]
  topic_arn = "${aws_sns_topic.sns-notiify-lambda-evaluate.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.lambda-evaluate.arn}"
}

resource "aws_lambda_permission" "with_sns" {
  depends_on = [
      "aws_sns_topic_subscription.lambda"
  ]

  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.lambda-evaluate.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.sns-notiify-lambda-evaluate.arn}"
}

resource "aws_cloudwatch_metric_alarm" "alarm-errors-lambda-initiate-evaluation" {
  depends_on = [
      "aws_lambda_function.lambda-initiate"
  ]
  alarm_name          = "/${aws_lambda_function.lambda-initiate.function_name}LambdaError"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "3600"
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"


  alarm_actions = [
    "${var.SNSIdentificationErrors}",
  ]

  ok_actions = [
    "${var.SNSIdentificationErrors}",
  ]

  dimensions {
    FunctionName = "${aws_lambda_function.lambda-initiate.function_name}"
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm-errors-lambda-evaluate-evaluation" {
  depends_on = [
      "aws_lambda_function.lambda-evaluate"
  ]
  alarm_name          = "/${aws_lambda_function.lambda-evaluate.function_name}LambdaError"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "3600"
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"


  alarm_actions = [
    "${var.SNSIdentificationErrors}",
  ]

  ok_actions = [
    "${var.SNSIdentificationErrors}",
  ]

  dimensions {
    FunctionName = "${aws_lambda_function.lambda-evaluate.function_name}"
  }
}