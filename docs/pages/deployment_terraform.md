---
title: Deploying with Terraform
keywords: Terraform
sidebar: mydoc_sidebar
permalink: deployment_terraform.html
---

You should perform the following steps to deploy Dow Jones Hammer using Terraform:

1. Accomplish the preliminary steps
2. Configure AWS CLI access credentials
3. Edit Terraform configuration files
4. Launch Dow Jones Hammer deployment
5. Check Terraform output variables

## 1. Preliminary Steps

Check [this section](configuredeploy_overview.html#2-preliminary-steps) to make sure you have performed all necessary steps before proceeding further.


## 2. Configure AWS CLI Access Credentials

Terraform requires that AWS CLI has administrative access to the master account for Dow Jones Hammer deployment and slave accounts for Dow Jones Hammer to use. You should configure [named profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html) for each of your accounts.
To do it, proceed as follows:

1. Generate [API access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey) for your master account and slave accounts.
2. Create ```credentials``` file in the ```~/.aws/``` directory to configure AWS CLI.
3. Add account profiles to ```~/.aws/credentials```:

Sample configuration for the master account:

```
[hammer-master]
aws_access_key_id = xxx
aws_secret_access_key = xxx
```

Sample configuration for two slave accounts:

```
[hammer-slave1]
aws_access_key_id = yyy
aws_secret_access_key = yyy

[hammer-slave2]
aws_access_key_id = zzz
aws_secret_access_key = zzz
```


## 3. Edit Terraform Configuration Files

You can find Terraform templates in ```hammer/deployment/terraform/``` directory.

You should edit both ```terraform.tf``` and ```variables.tf``` files.


### 3.1. The terraform.tf File

You should edit the ```terraform.tf``` file to configure Terraform providers and cross-account role modules.

#### 3.1.1. Configure Providers

You should add ```provider``` sections for the master account and the slave account(s).

**Note**: ```profile``` values in the `provider` sections have to match AWS CLI profile names you configured during [Configure AWS CLI Access Credentials](#2-configure-aws-cli-access-credentials) step.

**Note**: `region` value has to match `aws.region` parameter you configured in [config.json](/editconfig.html#11-master-aws-account-settings).

Sample configuration for the master account:

```
 provider "aws" {
     region = "eu-west-1"
     profile = "hammer-master"
 }
```

Sample configuration for two slave accounts:

```
provider "aws" {
     alias = "hammer-slave1"
     region = "eu-west-1"
     profile = "hammer-slave1"
}

provider "aws" {
     alias = "hammer-slave2"
     region = "eu-west-1"
     profile = "hammer-slave2"
}
```

#### 3.1.2. Include cross-account role modules for each slave account

You should include and configure a cross-account role module for each slave account.

While editing this section, please note that:
* module `name` in the block header has to be unique for each slave account
* ```name``` value has to be unique for each slave account
* ```providers.aws``` value has to match the provider alias configured during the [Configure Providers](#311-configure-providers) step.

Sample configuration for two modules:

```
module "roles-crossaccount1" {
     source = "modules/roles-crossaccount"
     name = "hammer-slave1"
     providers = {
         aws = "aws.hammer-slave1"
     }
     masterAccountId = "${data.aws_caller_identity.master.account_id}"
     identificationCrossAccountIAMRole = "${var.identificationCrossAccountIAMRole}"
     reportingRemediationIAMCrossAccountRole = "${var.reportingRemediationIAMCrossAccountRole}"
     resources-prefix = "${var.resources-prefix}"
}

module "roles-crossaccount2" {
     source = "modules/roles-crossaccount"
     name = "hammer-slave2"
     providers = {
         aws = "aws.hammer-slave2"
     }
     masterAccountId = "${data.aws_caller_identity.master.account_id}"
     identificationCrossAccountIAMRole = "${var.identificationCrossAccountIAMRole}"
     reportingRemediationIAMCrossAccountRole = "${var.reportingRemediationIAMCrossAccountRole}"
     resources-prefix = "${var.resources-prefix}"
}

 ```

### 3.2. The variables.tf File

Terraform needs to pass a number of parameters to CloudFormation to create the CloudFormation stacks for Dow Jones Hammer:

| <center>Variable Name</center>    | <center>Variable Description</center>                                   |Default Value                  |
| ----------------------------------| ------------------------------------------------------------------------|:-----------------------------:|
|`identificationCheckRateExpression`| CloudWatch Schedule Cron Expression for the interval between Dow Jones Hammer identification runs **without minutes part** |`* * * ? *`  |
|`s3bucket`                         | S3 bucket you [created](configuredeploy_overview.html#24-create-s3-buckets-for-hammer) to deploy Dow Jones Hammer | `hammer-deploy-bucket` |
|`identificationIAMRole`            | Name of the identification IAM role to create in master account            |`cloudsec-master-id`    |
|`identificationCrossAccountIAMRole`| Name of the identification IAM role to create in slave accounts            |`cloudsec-crossact-id`  |
|`ec2InstanceType`                  | Instance type of the reporting/remediation EC2                             |`t2.small`                     |
|`reportingRemediationIAMRole`      | Name of the reporting/remediation IAM role to create in master account     |`cloudsec-master-ec2`   |
|`reportingRemediationIAMCrossAccountRole`| Name of the reporting/remediation IAM role to create in slave AWS accounts |`cloudsec-crossact-ec2` |
|`keyPair`                          | Name of the EC key pair you have created at [preliminary steps](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer) |``` joe.bloggs ``` |
|`vpcId`                            | ID of the VPC for deployment of the reporting/remediation EC2              |`vpc-2dedc54a`    |
|`subnet`                           | ID of the Subnet for deployment of the reporting/remediation EC2           |`subnet-37d28b50` |
|`lambdaSubnets`                    | IDs of VPC Subnets for deployment of identification lambdas (**optional**)         | |
|`lambdaSecurityGroups`             | IDs of VPC Security Groups for deployment of identification lambdas (**optional**) | |
|`resources-prefix`                 | The prefix for all Dow Jones Hammer resources                              |`hammer-`         |
|`tag`                              | Map with tags to apply to AWS resources                                    |`{}`              |

**Note**: Make sure that DynamoDB tables prefix is consistent with **ddb.table_name** for [all issue configurations](editconfig.html#2-configure-issue-specific-hammer-configuration-parameters) and [credentials](editconfig.html#13-reporting-setup-jiraslack) table name.

Sample ```variables.tf```:
```
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
    default = "joe.bloggs"
}
variable "vpcId" {
    default = "vpc-2dedc54a"
}
variable "subnet" {
    default = "subnet-37d28b50"
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
        environment = "prod"
        owner = "admin@example.com"
        product = "hammer"
    }
}
```

## 4. Launch Dow Jones Hammer Deployment

To launch Dow Jones Hammer deployment, run the following commands in ```hammer/deployment/terraform/``` directory:
```
terraform init
terraform apply
```

## 5. Check Terraform output variables

After successful Terraform deployment a few variables, you may be interested in, will be shown back:
* **ApiUrl**: URL for quering Dow Jones Hammer REST API
* **ReportingRemediationPrivateIP**: private IP address of reporting and remediation EC2 instance  
* **ReportingRemediationPublicIP**: public IP address of reporting and remediation EC2 instance

Sample output:
``` 
ApiUrl = https://qosfsduzasrh.execute-api.<region>.amazonaws.com/LATEST/
ReportingRemediationPrivateIP = 172.16.x.x
ReportingRemediationPublicIP = w.x.y.z
```