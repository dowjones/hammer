---
title: Elasticsearch Domain public access
keywords: playbook22
sidebar: mydoc_sidebar
permalink: playbook22_elasticsearch_public_access.html
---

# Playbook 22: Elasticsearch publicly accessible domains

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect Elasticsearch domains that are publicly accessible

## 1. Issue Identification

Dow Jones Hammer identifies those Elasticsearch domains for public access policy attached.

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/elasticsearch-public-access-domain-identification/initiate_to_desc_elasticsearch_public_access_domains.py`|
|Identification|`hammer/identification/lambdas/elasticsearch-public-access-domain-identification/describe_elasticsearch_public_access_domains.py`        |

## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected Elasticsearch domains. In case when such tag **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_elasticsearch_public_access_issue_tickets.py
```

## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can configure automatic remediation of issues. It means that in case Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration, the Dow Jones Hammer remediation job will adjust Elasticsearch Domain policy to eliminate this vulnerability.

In this specific case, Dow Jones Hammer restricts public statement by adding (or changing) `IpAddress` condition value that allow access only for IP addresses defined in [RFC 1918 - Address Allocation for Private Internets](https://tools.ietf.org/html/rfc1918).

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_elasticsearch_policy_permissions.py
```

### 3.2 Manual

To retain full control on the remediation functionality you can disable automatic remediation in [config.json](#41-the-configjson-file) and launch it manually:
1. Login to Dow Jones Hammer reporting and remediation EC2 via SSH with **centos** user and ssh key you created during [deployment](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer): `ssh -l centos -i <private_key> <EC2_IP_Address>`
2. Become **root** user: `sudo su -`
3. Change directory to Dow Jones Hammer sources: `cd /hammer-correlation-engine`
4. Launch Dow Jones Hammer remediation script: `python3.6 -m remediation.clean_elasticsearch_policy_permissions`
5. Confirm or refuse remediation of each issue separately


## 4. Setup Instructions For This Issue

To configure the detection, reporting, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify and report issues of this type, you should add the following parameters in the **es_public_access_domain** section of the **config.json** file:

|Parameter Name                |Description                            | Default Value|
|------------------------------|---------------------------------------|:------------:|
|`enabled`                     |Toggles issue detection for this issue |`true`|
|`ddb.table_name`              |Name of the DynamoDB table where Dow Jones Hammer will store the identified issues of this type| `hammer-es-public-access-domain` |
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue type    |`false`|

Sample **config.json** section:
```
"es_public_access_domain": {
        "enabled": true,
        "ddb.table_name": "hammer-es-public-access-domain",
        "reporting": true,
        "remediation": false,
        "remediation_retention_period": 21
    },```

### 4.2. The whitelist.json File

You can define exceptions to the general automatic remediation settings for specific Elasticsearch Domains. To configure such exceptions, you should edit the **es_public_access_domain** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s)|
|:------------:|:-----------------:|
|AWS Account ID|Elasticsearch Domain Names(s)|

Sample **whitelist.json** section:
```
"es_public_access_domain": {
        "__comment__": "Detects publicly accessible Elasticsearch domains - domain ARNs.",
		"1234567890123": ["arn:aws:es:us-east-2:1234567890123:domain/new-domain"]
    },
```

### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for the issue reporting purposes.

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

|Lambda Function|CloudWatch Log Group Name                   |
|---------------|--------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-elasticsearch-public-access`|
|Identification |`/aws/lambda/hammer-describe-elasticsearch-public-access`|

### 5.2. Issue Reporting Logging

Dow Jones Hammer issue reporting functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                               |
|-----------|---------------------------------------------------------|
|Reporting  |`reporting.create_elasticsearch_public_access_issue_tickets`|
|Remediation  |`remediation.clean_elasticsearch_policy_permissions`|


### 5.3. Slack Reports

In case you have enabled Dow Jones Hammer and Slack integration, Dow Jones Hammer sends notifications about issue identification and reporting to the designated Slack channel and/or recipient(s).

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

|Key          |Type  |Description                       |Example                                         |
|-------------|:----:|----------------------------------|------------------------------------------------|
|`name`       |string|Elasticsearch domain name                 |`test-domain`                            |
|`arn`     |string|Elasticsearch Domain Arn       |`arn:aws:es:us-east-2:1234567890123:domain/test-domain`                                         |
|`tags`       |map   |Tags associated with Domain |`{"Name": "TestDomain", "service": "archive"}`|