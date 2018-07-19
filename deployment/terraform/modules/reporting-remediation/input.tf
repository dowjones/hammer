variable "s3bucket" {}
variable "ec2InstanceType" {}
variable "reportingRemediationIAMRole" {}
variable "lambdaLogsForwarderArn" {}
variable "keyPair" {}
variable "vpcId" {}
variable "subnet" {}

variable "resources-prefix" {}

variable "tags" {
    type = "map"
    default = {}
}