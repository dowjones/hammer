variable "identificationCheckRateExpression" {
    default = "* * * ? *"
}
variable "s3bucket" {
    default = "hammer-deploy-bucket"
}
variable "s3BackupBucket" {
    default = "hammer-backups-bucket"
}
variable "identificationIAMRole" {
    default = "cloudsec-master-id"
}
variable "identificationCrossAccountIAMRole" {
    default = "cloudsec-crossact-id"
}
variable "ec2InstanceType" {
    default = "t2.small"
}
variable "reportingRemediationIAMRole" {
    default = "cloudsec-master-ec2"
}
variable "reportingRemediationIAMCrossAccountRole" {
    default = "cloudsec-crossact-ec2"
}
variable "keyPair" {
    default = "id_rsa"
}
variable "vpcId" {
    default = "vpc-12345678"
}
variable "subnet" {
    default = "subnet-12345678"
}

variable "apiIAMRole" {
    default = "cloudsec-master-id"
}

variable "lambdaSubnets" {
    default = ""
}
variable "lambdaSecurityGroups" {
    default = ""
}

variable "resources-prefix" {
    default = "hammer-"
}

variable "tags" {
    type = "map"

    default = {

    }
}