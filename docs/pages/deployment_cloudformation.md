---
title: Deploying with CloudFormation
keywords: CloudFormation
sidebar: mydoc_sidebar
permalink: deployment_cloudformation.html
---

You should perform the steps mentioned below to deploy Dow Jones Hammer using CloudFormation:

1. Accomplish the preliminary steps
2. Put the Dow Jones Hammer packages into the Dow Jones Hammer deployment bucket
3. Deploy CloudFormation stacks to the master AWS account
4. Deploy CloudFormation stacks to the slave AWS accounts

## 1. Preliminary steps

Check [this section](configuredeploy_overview.html#2-preliminary-steps) to make sure you have performed all necessary steps before proceeding further.

## 2. Put the Dow Jones Hammer Packages to the Dow Jones Hammer Deployment Bucket

You should put the Dow Jones Hammer packages into the S3 bucket you have created to deploy Dow Jones Hammer. To do this, you can use the following AWS CLI command from the root of cloned Dow Jones Hammer sources:

```
aws s3 sync deployment/packages/ s3://hammer-deploy-bucket/
```

## 3. Deploy CloudFormation Stacks to the Master AWS Account

At this step, you should deploy the Dow Jones Hammer CloudFormation stacks to your master AWS account.
Number of stacks to deploy depends on the desired functionality:
* Identification only;
* Identification, Reporting and Remediation.

Additionally you can deploy API stack to use Dow Jones Hammer capabilities via REST API.

Choose json templates according to desired functionality from the table below and deploy them **in the same order** as they appear in the table:

1. Log in to the AWS Management Console and select **CloudFormation** in the **Services** menu.
2. Click **Create New Stack** in the **CloudFormation Stacks** main window.
3. On the **Select Template** page, select one of the json templates from the table below required for the desired functionality.
4. Choose **Next** and proceed to fill out the stack's parameters for which AWS CloudFormation will prompt you.
5. Set the desired AWS CloudFormation stack options. Check [AWS CloudFormation documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-add-tags.html) for details.
6. On the **Review** page, review the details of your stack.
7. When you've reviewed the details of your stack, click **Create** to complete stack creation.

| Dow Jones Hammer part               | JSON file with CloudFormation template                    | Identification | Identification,<br>Reporting and Remediation|
| ----------------------------------- | --------------------------------------------------------- |:--------------:|:------------------------:|
| IAM identification role             | `deployment/cf-templates/identification-role.json`        | **+**          | **+**                    |
| DynamoDB tables                     | `deployment/cf-templates/ddb.json`                        | **+**          | **+**                    |
| Identification functionality        | `deployment/cf-templates/identification.json`             | **+**          | **+**                    |
| API functionality                   | `deployment/cf-templates/api.json`                        | **+**          | **+**                    |
| IAM reporting/remediation role      | `deployment/cf-templates/reporting-remediation-role.json` |                | **+**                    |
| Reporting/remediation functionality | `deployment/cf-templates/reporting-remediation.json`      |                | **+**                    |

**Note**: you should deploy `DynamoDB tables`, `Identification functionality` and `Reporting/remediation functionality` CloudFormation stacks to the same AWS region as you configured in [aws.region](/editconfig.html#11-master-aws-account-settings) parameter of **config.json** file.

**Note**: note down **ApiUrl** value from the [API functionality](#316-api-functionality) stack [outputs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html) to access Dow Jones Hammer REST API.

**Note:** in case you intend to use Dow Jones Hammer reporting/remediation functionality:
1. Note down the value for the **LambdaLogsForwarderArn** from the [Identification functionality](#313-identification-functionality) stack [outputs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html) and provide it as an input parameter for the [Reporting/remediation functionality](#315-reportingremediation-functionality) stack.
2. Take into account that CloudFormation automatically discovers the latest version of CentOS 7 AMI and creates reporting and remediation EC2 instance from it. This functionality is implemented through the helper Lambda function and `Custom::AMIInfo` CloudFormation resource. In case of any problems with automating detection, check the corresponding Lambda CloudWatch Log Group - `/aws/lambda/hammer-ami-info`.
3. Note down values for the **ReportingRemediationPublicIP** and **ReportingRemediationPrivateIP** from the [Reporting and Remediation functionality](#315-reportingremediation-functionality) stack [outputs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html) to access reporting and remediation EC2 instance via SSH.

### 3.1. Parameters
Note: the value of **ResourcesPrefix** parameter must be the same in all stacks.

You will need to set the following parameters:

#### 3.1.1. IAM Identification Role
* **ResourcesPrefix**: the prefix for roles. The default value is **hammer-**.
* **IdentificationIAMRole**: the name of the identification IAM role to create in master account. The default value is **cloudsec-master-id**.
* **IdentificationCrossAccountIAMRole**: the name of the identification IAM role in slave accounts. The default value is **cloudsec-crossact-id**.

#### 3.1.2. DynamoDB Tables

* **ResourcesPrefix**: the prefix for Dow Jones Hammer DynamoDB tables. **Make sure** that DynamoDB table names are consistent with **ddb.table_name** for [all issue configurations](editconfig.html#2-configure-issue-specific-hammer-configuration-parameters) and [credentials](editconfig.html#13-reporting-setup-jiraslack) table name. The default value is **hammer-**.

#### 3.1.3. Identification Functionality

**Common parameters**:
* **ResourcesPrefix**: the prefix for all Dow Jones Hammer resources. The default value is **hammer-**.
* **S3BucketInfo**: the name of the S3 bucket you [created](configuredeploy_overview.html#24-create-s3-buckets-for-hammer) to deploy Dow Jones Hammer.
* **IdentificationIAMRole**: the name of identification IAM role for the Dow Jones Hammer identification functionality in master account. Use the same value as for **IdentificationIAMRole** parameter in [IAM Identification Role](#311-iam-identification-role) step. The default value is **cloudsec-master-id**.
* **IdentificationCheckRateExpression**: [CloudWatch Schedule Cron Expression](https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html#CronExpressions) for the interval between Dow Jones Hammer identification runs **without minutes part**. The default value is **\* * * ? \***.

**Sources**:
* **SourceLogsForwarder**: the relative path to the Lambda package that handles log forwarding from CloudWatch to Slack. The default value is **logs-forwarder.zip**.
* **SourceBackupDDB**: the relative path to the Lambda package that handles the backing up of DynamoDB tables. The default value is **ddb-tables-backup.zip**.
* **SourceIdentificationSG**: the relative path to the Lambda package that handles insecure services identification. The default value is **sg-issues-identification.zip**.
* **SourceIdentificationCloudTrails**: the relative path to the Lambda package that identifies CloudTrails issues. The default value is **cloudtrails-issues-identification.zip**.
* **SourceIdentificationS3ACL**: the relative path to the Lambda package that identifies public S3 bucket ACL-related issues. The default value is **s3-acl-issues-identification.zip**.
* **SourceIdentificationS3Policy**: the relative path to the Lambda package that identifies public S3 bucket policy-related issues. The default value is **s3-policy-issues-identification.zip**.
* **SourceIdentificationIAMUserKeysRotation**: the relative path to the Lambda package that identifies user key rotation issues. The default value is **iam-keyrotation-issues-identification.zip**.
* **SourceIdentificationIAMUserInactiveKeys**: the relative path to the Lambda package that identifies user inactive key issues. The default value is **iam-user-inactive-keys-identification.zip**.
* **SourceIdentificationEBSVolumes**: the relative path to the Lambda package that identifies EBS volume issues. The default value is **ebs-unencrypted-volume-identification.zip**.
* **SourceIdentificationEBSSnapshots**: the relative path to the Lambda package that identifies EBS snapshot issues. The default value is **ebs-public-snapshots-identification.zip**.
* **SourceIdentificationRDSSnapshots**: the relative path to the Lambda package that identifies RDS snapshot issues. The default value is **rds-public-snapshots-identification.zip**.
* **SourceIdentificationSQSPublicPolicy**: the relative path to the Lambda package that identifies SQS public queue issues. The default value is **sqs-public-policy-identification.zip**.
* **SourceIdentificationS3Encryption**: the relative path to the Lambda package that identifies S3 un-encrypted bucket issues. The default value is **s3-unencrypted-bucket-issues-identification.zip**.
* **SourceIdentificationRDSEncryption**: the relative path to the Lambda package that identifies RDS unencrypted instances. The default value is **rds-unencrypted-instance-identification.zip**.
* **SourceIdentificationAMIPublicAccess**: the relative path to the Lambda package that identifies Public AMIs. The default value is **ami-public-acess-issues-identification.zip**.

**VPC config (optional)**:
* **LambdaSubnets**: comma-separated list, without spaces, of subnet IDs in your VPC to run identification lambdas in.
* **LambdaSecurityGroups**: comma-separated list, without spaces, of Security Group IDs in your VPC to associate identification lambdas with.

#### 3.1.4. IAM Reporting/Remediation Role

* **SourceS3Bucket**: the name of [pre-created](configuredeploy_overview.html#24-create-s3-buckets-for-hammer) S3 deployment bucket.
* **S3BackupBucketName**: the name of [pre-created](configuredeploy_overview.html#24-create-s3-buckets-for-hammer) S3 backup bucket for the [remediation rollback functionality](remediation_backup_rollback.html).
* **ResourcesPrefix**: the prefix for roles. The default value is **hammer-**.
* **ReportingRemediationIAMRole**: the name of the reporting/remediation IAM role to create in master account. The default value is **cloudsec-master-ec2**.
* **ReportingRemediationIAMCrossAccountRole**: the name of the reporting/remediation IAM role in slave accounts. The default value is **cloudsec-crossact-ec2**.

#### 3.1.5. Reporting/Remediation Functionality

* **ResourcesPrefix**: the prefix for all Dow Jones Hammer resources. The default value is **hammer-**.
* **KeyPair**: name of the EC key pair you have created at [preliminary steps](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer).
* **InstanceType**: Instance type of the reporting/remediation EC2.
* **Vpcid**: the ID of the VPC for deployment of the reporting/remediation EC2.
* **Subnet**: the ID of the Subnet for deployment of the reporting/remediation EC2.
* **ReportingRemediationIAMRole**: the name of the reporting/remediation IAM role for the Dow Jones Hammer reporting/remediation functionality in master account. Use the same value as for **ReportingRemediationIAMRole** parameter in [IAM Reporting/Remediation Role](#314-iam-reportingremediation-role) step.
* **LambdaLogForwarderArn**: the ARN of the Lambda log forwarding function created during `Identification Functionality` deployment. Use the [output](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html) **LambdaLogsForwarderArn** value from [Identification Functionality](#313-identification-functionality) step.
* **SourceS3Bucket**: the name of the S3 bucket you [created](configuredeploy_overview.html#24-create-s3-buckets-for-hammer) to deploy Dow Jones Hammer.
* **SourceAMIInfo**: the relative path to the Lambda package with AMI autodetect code. The default value is **ami-info.zip**.
* **SourceReportingRemediation**: the relative path to the EC2 package with Dow Jones Hammer reporting and remediation sources. The default value is **reporting-remediation.zip**.

#### 3.1.6. API functionality

* **ResourcesPrefix**: the prefix for all Dow Jones Hammer resources. The default value is **hammer-**.
* **SourceS3Bucket**: the name of [pre-created](configuredeploy_overview.html#24-create-s3-buckets-for-hammer) S3 deployment bucket.
* **SourceApi**: the relative path to the Lambda package that implements REST API. The default value is **api.zip**.
* **IdentificationIAMRole**: the name of identification IAM role for the Dow Jones Hammer identification functionality in master account. Use the same value as for **IdentificationIAMRole** parameter in [IAM Identification Role](#311-iam-identification-role) step. The default value is **cloudsec-master-id**.

## 4. Deploy CloudFormation Stacks to the Slave AWS Accounts

At this step, you should deploy the Dow Jones Hammer CloudFormation stacks to each of your slave AWS accounts.
Number of stacks to deploy depends on the desired functionality (should be the same as you have chosen for your [master account](#3-deploy-cloudformation-stacks-to-the-master-aws-account)).

Choose json templates according to desired functionality from the table below and deploy them **in no particular order**:

1. Log in to the AWS Management Console and select **CloudFormation** in the **Services** menu.
2. Click **Create New Stack** in the **CloudFormation Stacks** main window.
3. On the **Select Template** page, select one of the json templates from the table below required for the desired functionality.
4. Choose **Next** and proceed to fill out the stack's parameters for which AWS CloudFormation will prompt you.
5. Set the desired AWS CloudFormation stack options. Check <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-add-tags.html">AWS CloudFormation documentation</a> for details.
6. On the **Review** page, review the details of your stack.
7. When you've reviewed the details of your stack, click **Create** to complete stack creation.

| Dow Jones Hammer part                       | JSON file with CloudFormation template                                 | Identification | Identification,<br>Reporting and remediation|
| ------------------------------------------- |------------------------------------------------------------------------|:--------------:|:------------------------:|
| IAM crossaccount identification role        | `deployment/cf-templates/identification-crossaccount-role.json`        | **+**          |                          |
| IAM crossaccount reporting/remediation role | `deployment/cf-templates/reporting-remediation-crossaccount-role.json` |                |  **+**                   |

### 4.1. Parameters

You will need to set the following parameters:

#### 4.1.1. IAM Cross-account Identification Role
* **ResourcesPrefix**: the prefix for role. The default value is **hammer-**.
* **MasterAccountID**: the AWS account ID of your master account.
* **IdentificationCrossAccountIAMRole**: the name of the cross-account role Dow Jones Hammer will assume to identify issues in slave AWS accounts. Use the same value as for `role_name_identification` parameter in the [configuration file](editconfig.html#11-master-aws-account-settings). The default value is **cloudsec-crossact-id**.

#### 4.1.2. IAM Cross-account Reporting/Remediation Role
* **ResourcesPrefix**: the prefix for role. The default value is **hammer-**.
* **MasterAccountID**: the AWS account ID of your master account.
* **ReportingRemediationIAMCrossAccountRole**: the name of the cross-account role Dow Jones Hammer will assume to report and remediate issues in slave AWS accounts. Use the same value as for `role_name_reporting` parameter in the [configuration file](editconfig.html#11-master-aws-account-settings). The default value is **cloudsec-crossact-ec2**.

The [trust relationship](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html) configuration for ```AssumeRole``` is included in the ```AssumeRolePolicyDocument``` sections of the cross-account role definitions.
