---
title: CloudTrail Logging Issues
keywords: playbook6
sidebar: mydoc_sidebar
permalink: playbook6_cloudtrail.html
---

# Playbook 6: CloudTrail Logging Issues

## Introduction

This playbook describes how to configure Dow Jones Hammer to address the issues with CloudTrail operation or log delivery in your accounts.

## 1. Issue Identification

Dow Jones Hammer checks the status of CloudTrail for the following triggers:

* CloudTrail is not enabled for any region;
* CloudTrail experiences problems with log delivery to S3 (permission denied);
* CloudTrail experiences problems with log delivery to CloudWatch (permission denied).

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions. The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/cloudtrails-issues-identification/initiate_to_desc_cloudtrails.py`|
|Identification|`hammer/identification/lambdas/cloudtrails-issues-identification/describe_cloudtrails.py`|

## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_cloudtrail_tickets.py
```

## 3. Issue Remediation

In this specific case, automated remediation **is not available**.

## 4. Setup Instructions For This Issue

To configure the detection and reporting of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify, report, and remediate issues of this type, you should add the following parameters in the **cloudtrails** section of the **config.json** file:

|Parameter Name                |Description                            | Default Value|
|------------------------------|---------------------------------------|:------------:|
|`enabled`                     |Toggles issue detection for this issue |`true`        |
|`ddb.table_name`              |Name of the DynamoDB table where Dow Jones Hammer will store the identified issues of this type|`hammer-cloudtrails`|
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue type    |`false`|

Sample **config.json** section:
```
"cloudtrails": {
    "enabled": "true",
    "ddb.table_name": "hammer-cloudtrails",
    "reporting": false,
}
```

### 4.2. The whitelist.json File

You can define exceptions to the general automatic remediation settings for specific AWS account regions. To configure such exceptions, you should edit the **cloudtrails** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|AWS Account ID|AWS Account Regions

Sample **whitelist.json** section:
```
"cloudtrails": {
    "123456789012": ["eu-west-1", "us-east-2"]
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

|Lambda Function|CloudWatch Log Group Name                |
|---------------|-----------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-cloudtrails`|
|Identification |`/aws/lambda/hammer-describe-cloudtrails`|

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name            |
|-----------|--------------------------------------|
|Reporting  |`reporting.create_cloudtrails_tickets`|
|Remediation|`remediation.clean_cloudtrails`       |

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

|Key              |Type   |Description                                             |Example                    |
|-----------------|:-----:|--------------------------------------------------------|---------------------------|
|`delivery_errors`|map    |CloudTrails which have logging issues                   |`{"ARN": {"errors": {...}, "events": "All", "multi_region": true}}`|
|`disabled`       |boolean|Indicates whether CloudTrail logging is disabled or not |`false` \| `true`          |
