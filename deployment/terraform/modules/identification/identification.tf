data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_lambda_function" "lambda-logs-forwarder" {
  depends_on = [
    "aws_cloudwatch_log_group.log-group-lambda-forwarder"
  ]
  function_name = "${var.resources-prefix}logs-forwarder"

  s3_bucket = "${var.s3bucket}"
  s3_key    = "${aws_s3_bucket_object.logs-forwarder.id}"

  description = "Lambda function for parsing logs"
  role    = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
  handler = "logs_forwarder.lambda_handler"
  runtime = "python3.6"
  timeout          = "300"
  memory_size      = "256"

}

resource "aws_cloudwatch_log_group" "log-group-lambda-forwarder" {
    name = "/aws/lambda/${var.resources-prefix}logs-forwarder"
    retention_in_days = 7
}

resource "aws_lambda_function" "lambda-backup-ddb" {
  depends_on = [
    "aws_cloudwatch_log_group.log-group-lambda-backup-ddb"
  ]
  function_name = "${var.resources-prefix}backup-ddb"

  s3_bucket = "${var.s3bucket}"
  s3_key    = "${aws_s3_bucket_object.ddb-tables-backup.id}"

  description = "Lambda function for parsing logs"
  role    = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
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
    "aws_cloudwatch_log_group.log-group-lambda-backup-ddb",
    "aws_lambda_permission.allow-cloudwatch-to-call-lambda-logs-forwarder",
    "aws_lambda_function.lambda-logs-forwarder"
  ]
  name = "${aws_cloudwatch_log_group.log-group-lambda-backup-ddb.name}"
  log_group_name  = "${aws_cloudwatch_log_group.log-group-lambda-backup-ddb.name}"
  filter_pattern  = "[level != START && level != END && level != DEBUG, ...]"
  destination_arn = "${aws_lambda_function.lambda-logs-forwarder.arn}"
}

resource "aws_cloudwatch_event_rule" "event-backup-ddb" {

    depends_on = [
      "aws_lambda_function.lambda-backup-ddb"
    ]

    name = "${var.resources-prefix}BackupDDB"
    description = "Hammer ScheduledRule for DDB tables backup"
    schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "check-backup-ddb" {
    depends_on = [
      "aws_cloudwatch_event_rule.event-backup-ddb"
    ]

    rule = "${aws_cloudwatch_event_rule.event-backup-ddb.name}"
    target_id = "lambda-backup-ddb"
    arn = "${aws_lambda_function.lambda-backup-ddb.arn}"
}

resource "aws_lambda_permission" "allow-cloudwatch-to-call-lambda-logs-forwarder" {
    depends_on = [
      "aws_lambda_function.lambda-logs-forwarder"
    ]

    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda-logs-forwarder.function_name}"
    principal = "logs.${data.aws_region.current.name}.amazonaws.com"
    source_arn = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"

}

resource "aws_lambda_permission" "allow-cloudwatch-to-call-lambda-backup-ddb" {
    depends_on = [
      "aws_lambda_function.lambda-backup-ddb", "aws_cloudwatch_event_rule.event-backup-ddb"
    ]

    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda-backup-ddb.function_name}"
    principal = "events.amazonaws.com"
    source_arn = "${aws_cloudwatch_event_rule.event-backup-ddb.arn}"

}


resource "aws_sns_topic" "sns-identification-errors" {
  name         = "${var.resources-prefix}identification-errors"
}

resource "aws_sns_topic_subscription" "lambda" {
  depends_on = [
      "aws_sns_topic.sns-identification-errors", "aws_lambda_function.lambda-logs-forwarder"
  ]
  topic_arn = "${aws_sns_topic.sns-identification-errors.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.lambda-logs-forwarder.arn}"
}

resource "aws_lambda_permission" "with_sns" {
  depends_on = [
      "aws_sns_topic.sns-identification-errors", "aws_lambda_function.lambda-logs-forwarder"
  ]

  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.lambda-logs-forwarder.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.sns-identification-errors.arn}"
}

resource "aws_cloudwatch_metric_alarm" "alarm-errors-lambda-backup-ddb" {
  depends_on = [
      "aws_lambda_function.lambda-backup-ddb", "aws_sns_topic.sns-identification-errors"
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
    "${aws_sns_topic.sns-identification-errors.arn}"
  ]

  ok_actions = [
    "${aws_sns_topic.sns-identification-errors.arn}"
  ]

  dimensions {
    FunctionName = "${aws_lambda_function.lambda-backup-ddb.arn}"
  }
}

module "hammer_id_nested_sg" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(35, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.sg-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateSecurityGroupLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify bad security groups"
    InitiateLambdaHandler = "initiate_to_desc_sec_grps.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifySecurityGroupLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe security groups unrestricted access."
    EvaluateLambdaHandler = "describe_sec_grps_unrestricted_access.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 512
    EventRuleName = "${var.resources-prefix}InitiateEvaluationSG"
    EventRuleDescription = "Hammer ScheduledRule to initiate Security Groups evaluations"
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameSecurityGroups}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameSecurityGroups}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_cloudtrails" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(15, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.cloudtrails-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateCloudTrailsLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate identification of CloudTrail issues."
    InitiateLambdaHandler = "initiate_to_desc_cloudtrails.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyCloudTrailsLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function for describe of CloudTrail issues."
    EvaluateLambdaHandler = "describe_cloudtrails.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 256
    EventRuleName = "${var.resources-prefix}InitiateEvaluationCloudTrails"
    EventRuleDescription = "Hammer ScheduledRule to initiate cloud trails evaluations"
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameCloudTrails}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameCloudTrails}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}


module "hammer_id_nested_s3_acl" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.s3-acl-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateS3ACLLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify public s3 buckets."
    InitiateLambdaHandler = "initiate_to_desc_s3_bucket_acl.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyS3ACLLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe public s3 buckets."
    EvaluateLambdaHandler = "describe_s3_bucket_acl.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationS3ACL"
    EventRuleDescription = "Hammer ScheduledRule to initiate S3 ACL evaluations"
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameS3ACL}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameS3ACL}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_s3_policy" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.s3-policy-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateS3PolicyLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify public s3 buckets."
    InitiateLambdaHandler = "initiate_to_desc_s3_bucket_policy.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyS3PolicyLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe public s3 buckets."
    EvaluateLambdaHandler = "describe_s3_bucket_policy.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationS3Policy"
    EventRuleDescription = "Hammer ScheduledRule to initiate S3 Policy evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameS3Policy}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameS3Policy}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}


module "hammer_id_nested_iam_user_keys_rotation" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.iam-keyrotation-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateIAMUserKeysRotationLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify IAM user keys which to be rotated."
    InitiateLambdaHandler = "initiate_to_desc_iam_users_key_rotation.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyIAMUserKeysRotationLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe IAM user keys to be rotated."
    EvaluateLambdaHandler = "describe_iam_key_rotation.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationIAMUserKeysRotation"
    EventRuleDescription = "Hammer ScheduledRule to initiate IAM user keys rotation evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameIAMUserKeysRotation}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameIAMUserKeysRotation}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_iam_user_inactive_keys" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.iam-user-inactive-keys-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateIAMUserInactiveKeysLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify IAM user keys which last used."
    InitiateLambdaHandler = "initiate_to_desc_iam_access_keys.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyIAMUserInactiveKeysLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe IAM user keys last used."
    EvaluateLambdaHandler = "describe_iam_accesskey_details.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationIAMUserInactiveKeys"
    EventRuleDescription = "Hammer ScheduledRule to initiate IAM user inactive keys evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameIAMUserInactiveKeys}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameIAMUserInactiveKeys}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}


module "hammer_id_nested_unencrypted_ebs_volumes" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.ebs-unencrypted-volume-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateEBSVolumesLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify unencrypted EBS volumes."
    InitiateLambdaHandler = "initiate_to_desc_ebs_unencrypted_volumes.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyEBSVolumesLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe unencrypted ebs volumes."
    EvaluateLambdaHandler = "describe_ebs_unencrypted_volumes.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationEBSVolumes"
    EventRuleDescription = "Hammer ScheduledRule to initiate EBS volumes evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameEBSVolumes}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameEBSVolumes}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_public_ebs_snapshots" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.ebs-public-snapshots-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateEBSSnapshotsLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify public EBS snapshots."
    InitiateLambdaHandler = "initiate_to_desc_ebs_public_snapshots.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyEBSSnapshotsLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe public ebs snapshots."
    EvaluateLambdaHandler = "describe_ebs_public_snapshots.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationEBSSnapshots"
    EventRuleDescription = "Hammer ScheduledRule to initiate ebs snapshots evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameEBSSnapshots}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameEBSSnapshots}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_public_rds_snapshots" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.rds-public-snapshots-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateRDSSnapshotsLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify public RDS snapshots."
    InitiateLambdaHandler = "initiate_to_desc_rds_public_snapshots.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyRDSSnapshotsLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe public RDS snapshots."
    EvaluateLambdaHandler = "describe_rds_public_snapshots.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationRDSSnapshots"
    EventRuleDescription = "Hammer ScheduledRule to initiate RDS snapshots evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameRDSSnapshots}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameRDSSnapshots}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_sqs_public_policy" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.sqs-public-policy-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateSQSPublicPolicyLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify public SQS queues."
    InitiateLambdaHandler = "initiate_to_desc_sqs_public_policy.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifySQSPublicPolicyLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe public SQS queues."
    EvaluateLambdaHandler = "describe_sqs_public_policy.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationSQSPublicPolicy"
    EventRuleDescription = "Hammer ScheduledRule to initiate SQS queue evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameSQSPublicPolicy}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameSQSPublicPolicy}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_s3_encryption" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.s3-unencrypted-bucket-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateS3EncryptionLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify S3 unencrypted buckets."
    InitiateLambdaHandler = "initiate_to_desc_s3_encryption.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyS3EncryptionLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe un-encrypted S3 buckets."
    EvaluateLambdaHandler = "describe_s3_encryption.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationS3Encryption"
    EventRuleDescription = "Hammer ScheduledRule to initiate S3 encryption evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameS3Encryption}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameS3Encryption}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_rds_encryption" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.rds-unencrypted-instance-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateRDSEncryptionLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify unencrypted RDS instances."
    InitiateLambdaHandler = "initiate_to_desc_rds_instance_encryption.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyRDSEncryptionLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe un-encrypted RDS instances."
    EvaluateLambdaHandler = "describe_rds_instance_encryption.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationRDSEncryption"
    EventRuleDescription = "Hammer ScheduledRule to initiate RDS encryption evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameRDSEncryption}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameRDSEncryption}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_ami_public_access" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.ami-public-access-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateAMIPublicAccessLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify public AMI access issues."
    InitiateLambdaHandler = "initiate_to_desc_public_ami_issues.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyAMIPublicAccessLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe public AMI issues."
    EvaluateLambdaHandler = "describe_public_ami_issues.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationAmiPublicAccess"
    EventRuleDescription = "Hammer ScheduledRule to initiate Ami public access evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameAMIPublicAccess}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameAMIPublicAccess}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_ecs_privileged_access" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.ecs-privileged-access-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateECSPrivilegedAccessLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify ECS privileged access issues."
    InitiateLambdaHandler = "initiate_to_desc_ecs_privileged_access_issues.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyECSPrivilegedAccessLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe ECS privileged access issues."
    EvaluateLambdaHandler = "describe_ecs_privileged_access_issues.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationECSPrivilegedAccess"
    EventRuleDescription = "Hammer ScheduledRule to initiate ECS privileged access evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameECSPrivilegedAccess}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameECSPrivilegedAccess}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}

module "hammer_id_nested_ecs_logging" {

    source    = "../identification-nested"
    tags = "${var.tags}"
    IdentificationIAMRole = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.resources-prefix}${var.identificationIAMRole}"
    IdentificationCheckRateExpression = "cron(10, ${var.identificationCheckRateExpression})"
    LambdaSubnets = "${var.lambdaSubnets}"
    LambdaSecurityGroups = "${var.lambdaSecurityGroups}"
    SourceBackupDDB = "${aws_s3_bucket_object.ddb-tables-backup.id}"
    SourceS3Bucket = "${var.s3bucket}"
    SourceIdentification =  "${aws_s3_bucket_object.ecs-logging-issues-identification.id}"
    InitiateLambdaName = "${var.resources-prefix}${var.initiateECSLoggingLambdaFunctionName}"
    InitiateLambdaDescription = "Lambda function for initiate to identify ECS logging enabled or not."
    InitiateLambdaHandler = "initiate_to_desc_ecs_logging_issues.lambda_handler"
    EvaluateLambdaName = "${var.resources-prefix}${var.identifyECSLoggingLambdaFunctionName}"
    EvaluateLambdaDescription = "Lambda function to describe ECS logging enabled or not."
    EvaluateLambdaHandler = "describe_ecs_logging_issues.lambda_handler"
    SourceLogsForwarder = "${aws_s3_bucket_object.logs-forwarder.id}"
    LambdaLogsForwarderArn =  "${aws_lambda_function.lambda-logs-forwarder.arn}"
    EvaluateLambdaMemorySize = 128
    EventRuleName = "${var.resources-prefix}InitiateEvaluationECSLogging"
    EventRuleDescription = "Hammer ScheduledRule to initiate ECS logging evaluations."
    SNSDisplayName = "${var.resources-prefix}${var.snsDisplayNameECSLogging}"
    SNSTopicName = "${var.resources-prefix}${var.snsTopicNameECSLogging}"
    SNSIdentificationErrors = "${aws_sns_topic.sns-identification-errors.arn}"
}
