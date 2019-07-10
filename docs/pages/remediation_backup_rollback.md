---
title: Remediation Backup and Rollback
keywords: Remediation
sidebar: mydoc_sidebar
permalink: remediation_backup_rollback.html
---

## 1. Overview

Dow Jones Hammer supports *remediation* for most issue types. Remediation means that, depending on the issue, Dow Jones Hammer makes configuration changes that reduce or remove a vulnerability/violation.

For some issues, Dow Jones Hammer saves the pre-remediation configuration. In case you wish to rollback the configuration changes that Dow Jones Hammer made, you can use the saved configuration to do it.

The following table gives an overview of Dow Jones Hammer remediation functionality for different issues. Refer to issue-specific playbooks for further details.

|<center>Issue Type</center>                                                           |Remediation|Remediation<br>Backup|
|--------------------------------------------------------------------------------------|:---------:|:-------------------:|
|[S3 ACL Public Access](playbook1_s3_public_buckets_acl.html#3-issue-remediation)      | Yes       | Yes                 |
|[Insecure Services](playbook2_insecure_services.html#3-issue-remediation)             | Yes       | Yes                 |
|[IAM User Inactive Keys](playbook3_inactive_user_keys.html#3-issue-remediation)       | Yes       | `No`                |
|[IAM User Key Rotation](playbook4_keysrotation.html#3-issue-remediation)              | Yes       | `No`                |
|[S3 Policy Public Access](playbook5_s3_public_buckets_policy.html#3-issue-remediation)| Yes       | Yes                 |
|[CloudTrail Logging Issues](playbook6_cloudtrail.html#3-issue-remediation)            | `No`      | `No`                |
|[EBS Unencrypted Volumes](playbook7_ebs_unencrypted_volumes.html#3-issue-remediation) | `No`      | `No`                |
|[EBS Public Snapshots](playbook8_ebs_snapshots_public.html#3-issue-remediation)       | Yes       | `No`                |
|[RDS Public Snapshots](playbook9_rds_snapshots_public.html#3-issue-remediation)       | Yes       | `No`                |
|[SQS Queue Public Access](playbook10_sqs_public_policy.html#3-issue-remediation)      | Yes       | Yes                 |
|[S3 Unencrypted Buckets](playbook11_s3_unencryption.html#3-issue-remediation)         | Yes       | Yes                 |
|[RDS Unencrypted instances](playbook12_rds_unencryption.html#3-issue-remediation)     | `No`      | `No`                |
|[AMIs Public Access](playbook13_amis_public_access.html#3-issue-remediation)     | `Yes`      | `No`                |

## 2. How Remediation Backup Works

For some remediation types ([check table above](#1-overview)), Dow Jones Hammer saves the pre-remediation configuration as a JSON snippet to the S3 bucket configured with **s3_backup_bucket** key in [Master AWS Account Settings](editconfig.html#11-master-aws-account-settings).

This table describes the paths and the naming convention of backup JSON files for supported issues:

|Issue Type             |<center>Backup Path Template</center>                                                       |<center>Backup Path Sample</center>                                                |
|-----------------------|--------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
|S3 ACL Public Access   |`bucket_acls/[account_id]/`<br>`[remediated_bucket_name]_[timestamp].json`                        |`bucket_acls/123456789012/hammer-test1_2018-03-26T15:58:46+00:00.json`             |
|S3 Policy Public Access|`bucket_policies/[account_id]/`<br>`[remediated_bucket_name]_[timestamp].json`                    |`bucket_policies/123456789012/hammer-test2_2018-03-27T10:24:45+00:00.json`         |
|Insecure Services      |`security_groups/[account_id]/`<br>`[region_code]/[remediated_security_group_ID]_[timestamp].json`|`security_groups/123456789012/eu-west-1/sg-123a456f_2018-04-12T14:46:14+00:00.json`|

As of now, there is no retention limit for remediation backups.

## 3. Remediation Rollback Instructions

The steps you should take to rollback an issue's remediation vary depending on the issue type.

### 3.1. S3 ACL Public Access Rollback

To rollback this issue's remediation, perform the following steps:

1. Sign in to the AWS Management Console and open the Amazon S3 console.
2. Find the S3 bucket you want to rollback ACL settings for.
3. Compare current S3 ACL settings with the settings in the backup JSON file.
4. Modify the ACL settings manually to match settings from the backup JSON file.

Refer to [ACL Bucket Permissions documentation](https://docs.aws.amazon.com/AmazonS3/latest/user-guide/set-bucket-permissions.html) for further details.

### 3.2. Insecure Services Rollback

To rollback this issue's remediation, perform the following steps:

1. Sign in to the AWS Management Console and open the Amazon EC2 console, `Security Groups` section.
2. Find the security group you want to rollback rules for.
3. Compare current security group rules with the rules in the backup JSON file.
4. Modify security group rules manually to match rules from the backup JSON file.

Refer to the [EC2 Security Groups documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#adding-security-group-rule) for details.

### 3.3. IAM User Inactive Keys

To rollback this issue's remediation, you need to [set this access key status](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) to ```Active``` using the AWS API or Management Console.

### 3.4. IAM User Key Rotation

To rollback this issue's remediation, you need to [set this access key status](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) to ```Active``` using the AWS API or Management Console.

### 3.5. S3 Policy Public Access Rollback

To rollback this issue's remediation, run the following command using the AWS CLI:
```
aws s3api put-bucket-policy --bucket [remediated_bucket_name] --policy [backup_file_name].json
```

### 3.6. EBS Public Snapshots

To rollback this issue's remediation, you need to add `group` `all` to `createVolumePermission` attribute using the [AWS API](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-snapshot-attribute.html) or [make snapshot public using Management Console](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html).

### 3.7. RDS Public Snapshots

To rollback this issue's remediation, you need to [make snapshot public](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html) using the AWS API or Management Console.

### 3.8. SQS Policy Public Access Rollback

To rollback this issue's remediation, run the following command using the AWS CLI:
```
aws sqs set-queue-attributes --queue-url [queue_url] --attributes [backup_file_name].json
```

### 3.9. S3 Unencrypted Buckets

To rollback a remediation of this issue, run the following command using the AWS CLI:
```
aws s3 put-bucket-encryption --bucket [bucket_name] --server-side-encryption-configuration [rules]
```