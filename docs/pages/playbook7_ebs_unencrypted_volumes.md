---
title: EBS Unencrypted Volumes
keywords: playbook7
sidebar: mydoc_sidebar
permalink: playbook7_ebs_unencrypted_volumes.html
---

# Playbook 7: EBS Unencrypted Volumes

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect EBS Volumes that are not encrypted at rest (as required by the PCI compliance rules).


## 1. Issue Identification

Dow Jones Hammer identifies those EBS volumes for which ```encrypted``` parameter value is ```false```.

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/ebs-unencrypted-volume-identification/initiate_to_desc_ebs_unencrypted_volumes.py`|
|Identification|`hammer/identification/lambdas/ebs-unencrypted-volume-identification/describe_ebs_unencrypted_volumes.py`|


## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected EBS volume and attached EC2 instances. In case when such tag **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_ebs_unencrypted_volume_issue_tickets.py
```

## 3. Issue Remediation

In this specific case, automated remediation **is not available**.

## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify, report, and remediate issues of this type, you should add the following parameters in the **ebs_unencrypted_volume** section of the **config.json** file:

|Parameter Name|Description|Default Value|
|----------------|----------------------------------------------------------------------------------------|:-------------------------------:|
|`enabled`       |Toggles issue detection for this issue                                                  |`true`                           |
|`ddb.table_name`|The name of the DynamoDB table to which Dow Jones Hammer would record detected issues of this type|`hammer-ebs-volumes-unencrypted` |
|`accounts`      |*Optional* comma-separated list of accounts to limit check for                          |`aws.accounts` from `config.json`|
|`reporting`     |Toggle Dow Jones Hammer reporting functionality for this issue                                    |`false`                          |

Sample **config.json** section:
```
"ebs_unencrypted_volume": {
    "enabled": "true",
    "ddb.table_name": "hammer-ebs-volumes-unencrypted",
    "accounts": ["210987654321"],
    "reporting": false,
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection settings for specific EBS volumes. To configure such exceptions, you should edit the  **ebs_unencrypted_volume** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|AWS Account ID|EBS Volume IDs

Sample **whitelist.json** section:
```
"ebs_unencrypted_volume": {
    "123456789012": ["vol-03ddaf8f4aef1b1f4", "vol-004186f485f2d57c7"]
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

|Lambda Function|CloudWatch Log Group Name                            |
|---------------|-----------------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-ebs-unencrypted-volumes`|
|Identification |`/aws/lambda/hammer-describe-ebs-unencrypted-volumes`|

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                        |
|-----------|--------------------------------------------------|
|Reporting  |`reporting.create_ebs_unencrypted_volumes_tickets`|

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

|Key          |Type  |Description                                                |Example                          |
|-------------|:----:|-----------------------------------------------------------|---------------------------------|
|`name`       |string|EBS volume name                                            |`my-test-volume`                 |
|`region`     |string|AWS region code where volume exists                        |`eu-west-1`                      |
|`state`      |string|EBS volume state                                           |`available`                      |
|`attachments`|map   |EC2 instances attached to volume                           |`{"i-0b3075135532d2051": "attached"}`         |
|`tags`       |map   |Tags associated with bucket                                |`{"Name": "TestVolume", "service": "gluster"}`|
