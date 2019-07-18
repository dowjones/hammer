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

variable "snsDisplayNameCloudTrails" {
    default = "describe-cloudtrails-sns"
}

variable "snsTopicNameCloudTrails" {
    default = "describe-cloudtrails-lambda"
}

variable "snsDisplayNameS3Policy" {
    default = "describe-s3-policy-sns"
}

variable "snsTopicNameS3Policy" {
    default = "describe-s3-policy-lambda"
}

variable "snsDisplayNameIAMUserKeysRotation" {
    default = "describe-iam-key-rotation-sns"
}

variable "snsTopicNameIAMUserKeysRotation" {
    default = "describe-iam-key-rotation-lambda"
}

variable "snsDisplayNameIAMUserInactiveKeys" {
    default = "describe-iam-user-inactive-keys-sns"
}

variable "snsTopicNameIAMUserInactiveKeys" {
    default = "describe-iam-user-inactive-keys-lambda"
}

variable "snsDisplayNameEBSVolumes" {
    default = "describe-ebs-volumes-sns"
}

variable "snsTopicNameEBSVolumes" {
    default = "describe-ebs-unencrypted-volumes-lambda"
}

variable "snsDisplayNameEBSSnapshots" {
    default = "describe-ebs-snapshots-sns"
}

variable "snsTopicNameEBSSnapshots" {
    default = "describe-ebs-public-snapshots-lambda"
}

variable "snsDisplayNameRDSSnapshots" {
    default = "describe-rds-snapshots-sns"
}

variable "snsTopicNameRDSSnapshots" {
    default = "describe-rds-public-snapshots-lambda"
}

variable "snsDisplayNameAMIPublicAccess" {
    default = "describe-ami-public-access-sns"
}

variable "snsTopicNameAMIPublicAccess" {
    default = "describe-ami-public-access-lambda"
}

variable "snsDisplayNameSQSPublicPolicy" {
    default = "describe-sqs-public-policy-sns"
}

variable "snsTopicNameSQSPublicPolicy" {
    default = "describe-sqs-public-policy-lambda"
}

variable "snsDisplayNameS3Encryption" {
    default = "describe-s3-encryption-sns"
}

variable "snsTopicNameS3Encryption" {
    default = "describe-s3-encryption-lambda"
}

variable "snsDisplayNameRDSEncryption" {
    default = "describe-rds-encryption-sns"
}

variable "snsTopicNameRDSEncryption" {
    default = "describe-rds-encryption-lambda"
}

variable "snsDisplayNameECSPrivilegedAccess" {
    default = "describe-ecs-privileged-access-sns"
}

variable "snsTopicNameECSPrivilegedAccess" {
    default = "describe-ecs-privileged-access-lambda"
}

variable "snsDisplayNameECSLogging" {
    default = "describe-ecs-logging-sns"
}

variable "snsTopicNameECSLogging" {
    default = "describe-ecs-logging-lambda"
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

variable "identifyCloudTrailsLambdaFunctionName" {
    default = "describe-cloudtrails"
}

variable "initiateCloudTrailsLambdaFunctionName" {
    default = "initiate-cloudtrails"
}

variable "identifyS3PolicyLambdaFunctionName" {
    default = "describe-s3-policy"
}

variable "initiateS3PolicyLambdaFunctionName" {
    default = "initiate-s3-policy"
}

variable "identifyIAMUserKeysRotationLambdaFunctionName" {
    default = "describe-iam-key-ratation"
}

variable "initiateIAMUserKeysRotationLambdaFunctionName" {
    default = "initiate-iam-key-ratation"
}

variable "initiateAMIPublicAccessLambdaFunctionName" {
    default = "initiate-ami-public-access"
}

variable "identifyAMIPublicAccessLambdaFunctionName" {
    default = "describe-ami-public-access"
}

variable "initiateSQSPublicPolicyLambdaFunctionName" {
    default = "initiate-sqs-public-policy"
}

variable "identifySQSPublicPolicyLambdaFunctionName" {
    default = "describe-sqs-public-policy"
}

variable "initiateRDSSnapshotsLambdaFunctionName" {
    default = "initiate-rds-public-snapshots"
}

variable "identifyRDSSnapshotsLambdaFunctionName" {
    default = "describe-rds-public-snapshots"
}

variable "initiateS3EncryptionLambdaFunctionName" {
    default = "initiate-s3-encryption"
}

variable "identifyS3EncryptionLambdaFunctionName" {
    default = "describe-s3-encryption"
}

variable "initiateRDSEncryptionLambdaFunctionName" {
    default = "initiate-rds-encryption"
}

variable "identifyRDSEncryptionLambdaFunctionName" {
    default = "describe-rds-encryption"
}

variable "initiateECSPrivilegedAccessLambdaFunctionName" {
    default = "initiate-ecs-privileged-access"
}

variable "identifyECSPrivilegedAccessLambdaFunctionName" {
    default = "describe-ecs-privileged-access"
}

variable "initiateECSLoggingLambdaFunctionName" {
    default = "initiate-ecs-logging"
}

variable "identifyECSLoggingLambdaFunctionName" {
    default = "describe-ecs-logging"
}

variable "initiateEBSSnapshotsLambdaFunctionName" {
    default = "initiate-ebs-public-snapshots"
}

variable "identifyEBSSnapshotsLambdaFunctionName" {
    default = "describe-ebs-public-snapshots"
}

variable "initiateEBSVolumesLambdaFunctionName" {
    default = "initiate-ebs-unencrypted-volumes"
}

variable "identifyEBSVolumesLambdaFunctionName" {
    default = "describe-ebs-unencrypted-volumes"
}

variable "initiateIAMUserInactiveKeysLambdaFunctionName" {
    default = "initiate-iam-user-inactive-keys"
}

variable "identifyIAMUserInactiveKeysLambdaFunctionName" {
    default = "describe-iam-user-inactive-keys"
}
