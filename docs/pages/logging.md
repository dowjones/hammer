---
title: Logging
sidebar: mydoc_sidebar
permalink: logging.html
---

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for the issues you have enabled in the Dow Jones Hammer configuration files.

## 1. Issue Identification Logging

According to the [Dow Jones Hammer architecture](index.html#lifecycle-description), the issue identification functionality uses two Lambda functions.

You can see the logs for each of these Lambda functions in the following Log Groups:

|Lambda Function <br>Designation|CloudWatch Log Group <br>Name Template|
|:-------:|:-----------:|
|Initialization|``/aws-lambda/hammer-initiate-[ISSUE_DESIGNATION]``|
|Identification|``/aws-lambda/hammer-describe-[ISSUE_DESIGNATION]``|

In the table above, ```ISSUE_DESIGNATION``` is a placeholder for the issue-specific part of the Log Group name. You can find complete issue-specific Log Group names in the issue's playbook ([example](playbook1_s3_public_buckets_acl.html#51-issue-identification-logging)).

## 2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. This Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream <br>Name Template|
|:-------:|:-----------:|
|Reporting|``reporting.create_[ISSUE_DESIGNATION]_tickets``|
|Remediation|``remediation.clean_[ISSUE_DESIGNATION]``|

In the table above, ```ISSUE_DESIGNATION``` is a placeholder for the issue-specific part of the Log Stream name. You can find complete issue-specific Log Stream names in the issue's playbook ([example](playbook2_insecure_services.html#52-issue-reportingremediation-logging)).

## 3. Dow Jones Hammer Operations Logging

There are two Lambda functions that handle certain hammer-internal functions. The Log Groups for these Lambda functions are as follows:

|Log Group Name                         |Log Group Description                   |
|:-------------------------------------:|:--------------------------------------:|
|```/aws/lambda/hammer-backup-ddb```    |DynamoDB backup                         |
|```/aws/lambda/hammer-logs-forwarder```|Dow Jones Hammer log forwarding to Slack|

## 4. Dow Jones Hammer Log Forwarding to Slack

In case you have configured Dow Jones Hammer and Slack integration, Dow Jones Hammer forwards its logs to Slack. Log forwarding settings configuration is in the ```slack``` section of the **config.json** file.

Check the **config.json** configuration instructions for further details.

In case Dow Jones Hammer fails to forward logs to Slack, check ``/aws/lambda/hammer-logs-forwarder`` CloudWatch Log Group to investigate this issue.

**Note**: You can find instructions how to configure Slack integration [here](editconfig.html#13-reporting-setup-jiraslack), if needed. This integration is optional.

## 5. Using CloudWatch to Explore Dow Jones Hammer Logs

To access Dow Jones Hammer logs, proceed as follows:

1. Open **AWS Management Console**.
2. Select **CloudWatch** service.
3. Select **Logs** from the CloudWatch sidebar.
4. Select the Log Group you want to explore. The Log Group will open.
5. Select the Log Stream you want to explore.

Check [CloudWatch Logs documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html) for further guidance.

## 6. Logging Slave Account Access Problems

### 6.1. Slave Account Role Assumption Problems

In case of problems with assuming slave account role, Dow Jones Hammer will log corresponding error to CloudWatch Logs.

Sample log records:
```
Failed to assume role in Account(id='123456789012', name='Slave1', role='hammer-cloudsec-crossact-id'), access denied (sts:AssumeRole)
Failed to assume role in Account(id='123456789012', name='Slave1', region='eu-west-1', role='hammer-cloudsec-crossact-id'), access denied (sts:AssumeRole)
```

The log record includes:
* Slave account ID;
* Slave account hammer-internal name;
* Slave account region code (if applicable);
* Slave account role name Dow Jones Hammer assumes;
* AWS API call Dow Jones Hammer failed to perform because of access rights lack.

You can find the message in the Log Group (Log Stream) of the Python module that encountered the problem.

### 6.2. Slave Account Role Permissions Problems

In case Dow Jones Hammer successfully assumes the role in a slave account, but the assumed role lacks permissions to perform a specific action, Dow Jones Hammer will log corresponding error to CloudWatch Logs.

Sample log records:
```
Access denied in Account(id="123456789012", name="Slave1", region='eu-west-1', role='hammer-cloudsec-crossact-id') (ec2:DescribeSecurityGroups)
Access denied in Account(id="123456789012", name="Slave1", role='hammer-cloudsec-crossact-id') (s3:GetBucketAcl, resource='test-bucket')
```

The log record includes:
* Slave account ID;
* Slave account hammer-internal name;
* Slave account region code (if applicable);
* Slave account role name Dow Jones Hammer assumes;
* AWS API call Dow Jones Hammer failed to perform because of role access restrictions;
* Name of the slave account resource Dow Jones Hammer failed to access because of role access restrictions (if applicable).

You can find the message in the Log Group (Log Stream) of the Python module that encountered the problem.