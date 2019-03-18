---
title: Insecure Services
keywords: playbook1
sidebar: mydoc_sidebar
permalink: playbook2_insecure_services.html
---

# Playbook 2: Insecure Services (Public Access to Sensitive Ports Allowed)

## Introduction

This playbook describes how to configure Dow Jones Hammer to address the cases when certain sensitive ports in your AWS account(s) are publicly accessible.

## 1. Issue Identification

Detects security group rules which allow public access to designated sensitive ports.
For each rule which allows public access, Dow Jones Hammer checks if rule allows access from any IP address - `0.0.0.0/0`, `::/0` (**open completely**) or from some definite public ip addresses or networks (**open partly**).

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/sg-issues-identification/initiate_to_desc_sec_grps.py`|
|Identification|`hammer/identification/lambdas/sg-issues-identification/describe_sec_grps_unrestricted_access.py`|

## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected Security Group and associated EC2 instances. In case when such tag **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_security_groups_tickets.py
```

## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can set up automatic remediation of issues. It means that in case Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration, the Dow Jones Hammer remediation job will adjust the settings of security groups.

In this specific case, issue remediation means that Dow Jones Hammer will delete the portions of SecurityGroup configuration that allows such access.
Instead of them, Dow Jones Hammer will put the configuration settings that allow access to this port only for IP addresses defined in [RFC 1918 - Address Allocation for Private Internets](https://tools.ietf.org/html/rfc1918).

Dow Jones Hammer will save the pre-remediation SecurityGroup configuration to a S3 backup bucket. You can use this configuration to [rollback the automatic remediation manually](remediation_backup_rollback.html#32-insecure-services-rollback), if necessary.

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_security_groups.py
```

### 3.2 Manual

To retain full control on the remediation functionality you can disable automatic remediation in [config.json](#41-the-configjson-file) and launch it manually:
1. Login to Dow Jones Hammer reporting and remediation EC2 via SSH with **centos** user and ssh key you created during [deployment](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer): `ssh -l centos -i <private_key> <EC2_IP_Address>`
2. Become **root** user: `sudo su -`
3. Change directory to Dow Jones Hammer sources: `cd /hammer-correlation-engine`
4. Launch Dow Jones Hammer remediation script: `python3.6 -m remediation.clean_security_groups`
5. Confirm or refuse remediation of each issue separately


## 4.  Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify, report, and remediate issues of this type, you should add the following parameters in the **secgrp_unrestricted_access** section of the **config.json** file:

|Parameter Name                |Description                            | Default Value|
|------------------------------|---------------------------------------|:------------:|
|`enabled`                     |Toggles issue detection for this issue |`true`        |
|`ddb.table_name`              |Name of the DynamoDB table where Dow Jones Hammer will store the identified issues of this type| `hammer-security-groups-unrestricted`|
|`accounts`                    |*Optional* comma-separated list of accounts to check and report for this issue type | **aws.accounts** from [config.json](editconfig.html#11-master-aws-account-settings) |
|`remediation_accounts`        |*Optional* comma-separated list of accounts to remediate this issue type            | **aws.accounts** from [config.json](editconfig.html#11-master-aws-account-settings) |
|`restricted_ports`            |Comma-separated list of ports for which you want to restrict public access |`[21, 22, 23, 3389,1433,1521,3306,5432, 27017]`|
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue type    |`false`|
|`remediation`                 |Toggle Dow Jones Hammer automatic remediation functionality for this issue type |`false`|
|`remediation_retention_period`|The amount of days to pass between issue detection and its automatic remediation. The value `0` denotes that Dow Jones Hammer will remediate the issue at the next remediation job run.|`21`|

Sample **secgrp_unrestricted_access** section of the **config.json** file:

```
"secgrp_unrestricted_access": {
    "enabled": "true",
    "ddb.table_name": "hammer-security-groups-unrestricted",
    "restricted_ports": [21, 22, 23, 3389, 1433, 1521, 3306, 5432, 27017],
    "reporting": false,
    "remediation": false,
    "remediation_retention_period": 21
}
```

### 4.2. The whitelist.json File

You can define exceptions to the general automatic remediation settings for specific security groups. To configure such exceptions, you should edit the  **secgrp_unrestricted_access** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:------------:|:------------------:|
|AWS Account ID|Security Group ID<br>VPC ID and Security Group Name, separated by colon|

Sample **whitelist.json** section:

```
"secgrp_unrestricted_access": {
    "123456789012": ["sg-7c228307", "sg-21f2ad5b", "vpc-654321:default"],
    "067463091988": ["vpc-123456:PAN-Dataplane_sg"]
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

|Lambda Function|CloudWatch Log Group Name                    |
|---------------|---------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-security-groups`|
|Identification |`/aws/lambda/hammer-describe-security-groups`|

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                |
|-----------|------------------------------------------|
|Reporting  |`reporting.create_security_groups_tickets`|
|Remediation|`remediation.clean_security_groups`       |

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

|Key      |Type        |Description                                |Example                            |
|---------|:----------:|-------------------------------------------|-----------------------------------|
|`name`   |string      |Security group name                        |`test-user`                        |
|`region` |string      |AWS region code where security group exists|`eu-west-1`                        |
|`status` |string      |Restriction status                         |`open_completely` \| `open_partly` |
|`perms`  |list of maps|Security group rules which violate policy  |`[{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0", "status": "open_completely"}]`|
|`tags`   |map         |Tags associated with security group        |`{"Name": "TestSG", "Env": "prod"}`|
