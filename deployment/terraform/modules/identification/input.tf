variable "identificationCheckRateExpression" {}
variable "s3bucket" {}
variable "identificationIAMRole" {}
variable "lambdaSubnets" {}
variable "lambdaSecurityGroups" {}

variable "resources-prefix" {}

variable "tags" {
    type = "map"
    default = {}
}