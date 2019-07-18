variable "InitiateLambdaName" {}
variable "SourceS3Bucket" {}
variable "SourceIdentification" {}
variable "InitiateLambdaDescription" {}
variable "IdentificationIAMRole" {}
variable "InitiateLambdaHandler" {}
variable "LambdaLogsForwarderArn" {}
variable "EvaluateLambdaName" {}
variable "EvaluateLambdaDescription" {}
variable "EvaluateLambdaHandler" {}
variable "EvaluateLambdaMemorySize" {}
variable "LambdaSubnets" {}
variable "LambdaSecurityGroups" {}
variable "EventRuleName" {}
variable "EventRuleDescription" {}
variable "IdentificationCheckRateExpression" {}
variable "SNSDisplayName" {}
variable "SNSTopicName" {}
variable "SNSIdentificationErrors" {}
variable "SourceLogsForwarder" {}
variable "SourceBackupDDB" {}

variable "tags" {
    type = "map"
    default = {}
}