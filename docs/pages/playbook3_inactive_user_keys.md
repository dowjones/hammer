---
title: IAM User Inactive Keys
keywords: playbook1
sidebar: mydoc_sidebar
permalink: playbook3_inactive_user_keys.html
---

# Playbook 3: IAM User Inactive Keys

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect, report and remediate the cases when certain IAM user keys in your AWS accounts have not been used for more than the given number of days.

## 1. Issue Identification


Dow Jones Hammer checks the values of the following IAM user key parameters:

1. ```LastUsedDate``` (in case it exists)
2. ```CreateDate``` (in case ```LastUsedDate``` is missing, because the key has not been used yet).

In case the values of one or both of these parameters do not match the Dow Jones Hammer configuration, Dow Jones Hammer detects an issue and makes a record to the designated DynamoDB table.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/iam-user-inactive-keys-identification/initiate_to_desc_iam_access_keys.py`|
|Identification|`hammer/identification/lambdas/iam-user-inactive-keys-identification/describe_iam_accesskey_details.py`|


## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_iam_key_inactive_tickets.py
```

## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can set up automatic remediation of issues. It means that if Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration, the Dow Jones Hammer remediation job will adjust the IAM user key settings to eliminate this vulnerability.

In this specific case, Dow Jones Hammer will set status of the detected user key(s) to ```Inactive```. This means that the key(s) cannot be used for API calls to AWS.

In case you need to rollback automatic remediation, refer to [the corresponding section](remediation_backup_rollback.html#33-iam-user-inactive-keys) of User Guide.

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_iam_keys_inactive.py
```

### 3.2 Manual

To retain full control on the remediation functionality you can disable automatic remediation in [config.json](#41-the-configjson-file) and launch it manually:
1. Login to Dow Jones Hammer reporting and remediation EC2 via SSH with **centos** user and ssh key you created during [deployment](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer): `ssh -l centos -i <private_key> <EC2_IP_Address>`
2. Become **root** user: `sudo su -`
3. Change directory to Dow Jones Hammer sources: `cd /hammer-correlation-engine`
4. Launch Dow Jones Hammer remediation script: `python3.6 -m remediation.clean_iam_keys_inactive`
5. Confirm or refuse remediation of each issue separately


## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify, report, and remediate issues of this type, you should add the following parameters in the **user_inactivekeys** section of the **config.json** file:

|Parameter Name                |Description                            | Default Value|
|------------------------------|---------------------------------------|:------------:|
|`enabled`                     |Toggles issue detection for this issue |`true`        |
|`ddb.table_name`              |Name of the DynamoDB table where Dow Jones Hammer will store the identified issues of this type| `hammer-iam-user-keys-inactive`|
|`accounts`                    |*Optional* comma-separated list of accounts to check and report for this issue type | **aws.accounts** from [config.json](editconfig.html#11-master-aws-account-settings) |
|`remediation_accounts`        |*Optional* comma-separated list of accounts to remediate this issue type            | **aws.accounts** from [config.json](editconfig.html#11-master-aws-account-settings) |
|`inactive_criteria_days`      |The threshold number of days for which a key has not been used; if exceeded, an issue will be detected|There is no default value, you should set it up explicitly|
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue type    |`false`|
|`remediation`                 |Toggle Dow Jones Hammer automatic remediation functionality for this issue type |`false`|
|`remediation_retention_period`|The amount of days to pass between issue detection and its automatic remediation. The value `0` denotes that Dow Jones Hammer will remediate the issue at the next remediation job run.|`0`|

Sample **config.json** section:
```
"user_inactivekeys": {
    "enabled": "true",
    "ddb.table_name": "hammer-iam-user-keys-inactive",
    "inactive_criteria_days": "10",
    "reporting": false,
    "remediation": false,
    "remediation_retention_period": 0
}
```

### 4.2 The whitelist.json File

You can define exceptions to the general automatic remediation settings for specific IAM user names or access keys. To configure such exceptions, you should edit the **user_inactivekeys** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|AWS Account ID|IAM user names or access keys |

Sample **whitelist.json** section:
```
"user_inactivekeys": {
    "123456789012": ["Joe.Bloggs@sample.com", "test-iam-access-key-user",
                     "AKIAI6UV7TCFQNA623TA", "AKIAIGZY37NNDDWXQNOA"]
}
```


### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for issue reporting purposes.

You can configure these parameters for specific AWS accounts and globally. Account-specific settings precede the global settings in the **ticket_owners.json** configuration file.

Check the following table for parameters:

|Parameter Name       |Description                                                         |Sample Value     |
|---------------------|--------------------------------------------------------------------|:---------------:|
|`jira_project`       |The name of the JIRA project where Dow Jones Hammer will create the issue     | `AWSSEC`        |
|`jira_owner`         |The name of the JIRA user to whom Dow Jones Hammer will assign the issue      | `Support-Cloud` |
|`jira_parent_ticket` |The JIRA ticket to which Dow Jones Hammer will link the new ticket it creates | `AWSSEC-1234`   |
|`slack_owner`        |Name(s) of the Slack channels (prefixed by `#`) and/or Slack users that will receive issue reports from Dow Jones Hammer | `["#devops-channel", "bob"]` |

Sample **ticket_owners.json** section:

Account-specific settings:
```
{
    "account": {
        "123456789012": {
            "jira_project": "",
            "jira_owner": "Support-Cloud",
            "jira_parent_ticket": "",
            "slack_owner": ""
        }
    },
    "jira_project": "AWSSEC",
    "jira_owner": "Support-General",
    "jira_parent_ticket": "AWSSEC-1234",
    "slack_owner": ["#devops-channel", "bob"]
}
```

## 5. Logging

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for this issue when you deploy Dow Jones Hammer.

### 5.1. Issue Identification Logging

Dow Jones Hammer issue identification functionality uses two Lambda functions:
* Initialization: this Lambda function selects slave accounts to check for this issue as designated in the Dow Jones Hammer configuration files and triggers the check.
* Identification: this Lambda function identifies this issue for each account/region selected at the previous step.

You can see the logs for each of these Lambda functions in the following Log Groups:

|Lambda Function|CloudWatch Log Group Name                           |
|---------------|----------------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-iam-user-inactive-keys`|
|Identification |`/aws/lambda/hammer-describe-iam-user-inactive-keys`|

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                       |
|-----------|-------------------------------------------------|
|Reporting  |`reporting.create_iam_user_inactive_keys_tickets`|
|Remediation|`remediation.clean_iam_user_inactive_keys`       |

### 5.3. Slack Reports

In case you have enabled Dow Jones Hammer and Slack integration, Dow Jones Hammer sends notifications about issue identification and remediation to the designated Slack channel and/or recipient(s).

Check [ticket_owners.json](#43-the-ticket_ownersjson-file) configuration for further guidance.

### 5.4. Using CloudWatch Logs for Dow Jones Hammer

To access Dow Jones Hammer logs, proceed as follows:

1. Open **AWS Management Console**.
2. Select **CloudWatch** service.
3. Select **Logs** from the CloudWatch sidebar.
4. Select the log group you want to explore. The log group will open.
5. Select the log stream you want to explore.

Check [CloudWatch Logs documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html) for further guidance.

## 6. Issue specific details in DynamoDB

Dow Jones Hammer stores various issue specific details in DynamoDB as a map under `issue_details` key. You can use it to create your own reporting modules.

|Key          |Type  |Description                                             |Example                    |
|-------------|:----:|--------------------------------------------------------|---------------------------|
|`create_date`|string|Date and time of access key creation in ISO 8601 format |`2018-02-14T16:48:02+00:00`|
|`last_used`  |string|Date and time of access key last usage in ISO 8601      |`2018-02-28T17:46:00+00:00`|
|`username`   |string|Username associated with access key                     |`test-user`                |
