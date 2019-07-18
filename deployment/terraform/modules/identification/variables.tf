variable "snsDisplayNameSecurityGroups" {
    default = "describe-security-groups-sns"
}

variable "snsTopicNameSecurityGroups" {
    default = "describe-security-groups-lambda"
}

variable "snsDisplayNameS3ACL" {
    default = "describe-s3-acl-sns"
}

variable "snsTopicNameS3ACL" {
    default = "describe-s3-acl-lambda"
}

variable "identifySecurityGroupLambdaFunctionName" {
    default = "describe-security-groups"
}

variable "initiateSecurityGroupLambdaFunctionName" {
    default = "initiate-security-groups"
}

variable "identifyS3ACLLambdaFunctionName" {
    default = "describe-s3-acl"
}

variable "initiateS3ACLLambdaFunctionName" {
    default = "initiate-s3-acl"
}

