---
title: Trusted Advisor Checks
keywords: playbook24
sidebar: mydoc_sidebar
permalink: playbook24_trusted_advisor_checks.html
---

# Playbook 24: Trusted Advisor Checks

## Introduction
Enabling Trusted Advisor checks with Hammer allows you to add all rules and checks from AWS’s Trusted Advisor with Dow Jones’ Hammer Continuous Monitoring Service.

File Structure:

```

├── trusted-advisor-checks-identification   <-- Parent folder for Trusted Advisor Checks
│   ├── README.md                           <-- This Instructions file
│   ├── initiate-ta-checks.py               <-- Initiate Lambda function
│   ├── describe-ta-checks.py               <-- Describe Lambda function

```

## 1. Issue Identification

Issues are flagged based on Trusted Advisor Checks. Please note, because these checks rely on the Trusted Advisor API and Support Access, only accounts that have some level of AWS Support can utilize this Hammer rule.

When Dow Jones Hammer detects an issue through Trusted Advisor, it writes the issue to the designated DynamoDB table.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/trusted-advisor-checks-identification/initiate_to_desc_ta_checks.py`|
|Identification|`hammer/identification/lambdas/trusted-advisor-checks-identification/describe_ta_checks.py`|

## 2. Issue Reporting and Remediation

Issue Reporting/Remediation is currently not enabled with Trusted Advisor checks, but could be a great feature add!


## 3. Setup Instructions For This Issue

In this section, we'll go through the configuration file, and all edits and additions you can make.

### 3.1. The config.json File
The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/configs/config.json`.
Review the following parameters in the **trusted-advisor-recommendations** section of the **config.json** file:

|Parameter Name                |Description                            | Default Value|
|------------------------------|---------------------------------------|:------------:|
|`enabled`                     |Toggles issue detection for this issue |`true`|
|`refreshtimeoutinminutes`     |Amount of time before the lambda initiate function is given to refresh trusted advisor checks| `8` |
|`checks`                      |A list of check objects with parameters that describe the specific Trusted Advisor checks.   |`[]`|

Each **check object** within the list of checks is comprised of the following:
|Parameter Name                |Description                            | Example|
|------------------------------|---------------------------------------|:------------:|
|`category`                     |The Trusted Advisor specified category. |`cost_optimizing`|
|`checkname`                    |The Trusted Advisor specified checkname.| `Low Utilization Amazon EC2 Instances` |
|`name`                         |User given name.   |`trusted_advisor_recommendations_low_ec2_utilization`|
|`accounts`                     |List of account IDs you'd like to enable the checks on. |`["12345678901","098765432109]"`|
|`filters`                      |A list of settings to filter the returned checks by. Default value is an empty list.   |`[]`|
|`ddb.table_name`               |The name of the dynamo table to hold all returned warnings from Trsuted Advisor. It is check specific and must exist in the environment! | `cost-optimizing-low-utilization-ec2-instances`

Below is a larger example of a config section!

```
{
    "trusted_advisor_recommendations": {
        "enabled": true,
        "refreshtimeoutinminutes": 8,
        "checks": [
            {
                "category": "cost_optimizing",
                "checkname": "Low Utilization Amazon EC2 Instances",
	            "name": "trusted_advisor_recommendations_low_ec2_utilization",
                "accounts": [
                    "Account ID 1",
                    "Account ID 2"
                ],
                "filters": [
                    {
                        "attribute": "Estimated Monthly Savings",
                        "operator": "gt",
                        "value": "500"
                    },
                    {
                        "attribute": "Number of Days Low Utilization",
                        "operator": "eq",
                        "value": "14",
                    }
                ],
                "ddb.table_name": "hammer-trusted-advisor-cost-optimizing-low-utilization-ec2-instances"
            },
            {
                "category": "fault_tolerance",
                "checkname": "Amazon EBS Snapshots",
                "accounts": [
                    "Account 1",
                    "Account 2"
                ],
                "filters": [
                    {
                        "attribute": "status",
                        "operator": "eq",
                        "value": "critical"
                    }
                ],
                "ddb.table_name": "hammer-trusted-advisor-fault-tolerance-ebs-snapshots"
            }
        ]
    }
}
```
### 3.2. How to configure Trusted Advisor checks

1. Turn on Trusted Advisor checks by changing "enabled" to true.
2. Configure "refreshtimeoutinminutes" to be how long the lambda function will wait for trusted advisor to refresh the check data.
3. Add a check to the "checks" list by specifying Trusted Advisor named category and checkname. Important to specify the EXACT checkname and category as returned by the Trusted Advisor API.
4. Specify the account ID's you would like to enable this TA check on.
5. Specify any filters you'd like to set. A filter tells Trusted Advisor which results to return by looking at the metadata of the check response. For example, for Low Util EC2 you can turn on a filter that looks at the Estimated Monthly Savings attribute and will only return EC2 instances where the Estimated Monthly Savings is greater than $500.
* Attribute must be the name of the category you'd like to filter the check by. To see the attributes of a result, look at the Trusted Advisor API call, trusted-advisor-describe-checks.

```$ aws support describe-trusted-advisor-checks --language en
```
All possible checks are returned. The metadata section explains possible attributes for a specific check.


* Operator - "eq" is equal, "gt" is greater than. The operator compares the current value from the describe-checks-result api call to the value specified in the 'value' field.

* Value - adjust depending on how you want to filter

See an example of the **filter** section below:
```
{
                        "attribute": "Number of Days Low Utilization",
                        "operator": "eq",
                        "value": "14",
                    }
```
If you do not want to filter the results, filters should be left as an empty list, like so:

```
filters: [],

```

6. "ddb.table_name" is the name of the Dynamo Table that stores the issue details returned from a Trusted Advisor check. The table must exist before the check can be enabled. DDB tables are check specific.

### 3.3. How to add your new check's DDB Table

Add your all ddb information to deployment/cf-templates/ddb.json:
1. Update the reference name of the table
2. “Key Schema”
    Must make the attributes account_id and issue_id
3. “BillingMode”: “PAY_PER_REQUEST”
4. “TableName”:
    Specify your table name,which will follow the resources prefix. This is the name of the table that you will reference in the config file as the new check's ddb.table_name.

### 3.4 Adding the checks to more Accounts
In config.json, go to the trusted_advisor_recommendations section, and add the account ID to each check object you want to enable on that account. Make sure that account has all updated permissions needed for Trusted Advisor checks. These permissions were updated in identificaiton-crossaccount-role.json.

## 4. Understanding the initiate and describe functions
The initiate function gathers all specifications from the config file, makes them account specific, and fans out the information to the describe function, creating X number of describe instances for X number of accounts specified in config.

account_and_checks: A dictionary to organize check information PER account. Each account object is taken in by a different describe instance. One account per describe instance.
```
          {
              AccountID1: {
                account_id: string,
                checks_info: [{}],
                client: account support client,
                refresh_done: boolean
            },
              AccountID2: {
                account_id: string,
                checks_info: [{}],
                client: account support client,
                refresh_done: boolean
            }
          }
```
checks_info is a list of check objects:
```
      {
        "checkname" : checkname,
        "id" : check_id,
        "name": name,
        "category": category,
        "metadata" : metadata,
        "ddb.table_name" : ddb,
        "filters": filters,
        "refresh_done" : False
        }
```
In each describe instance, the function gathers the Trusted Advisor result for each specific check enabled for the Account. This is where the Trusted Advisor API call to **describe-trusted-advisor-check-result(checkID)** will be made to actually gather the results. Results may be filtered depending on the config settings. They are then sent to Dynamo DB for the specific check.

## 5. Understanding Trusted Advisor API
Below will outline what the initiate and describe functions are doing with regard to making Trusted Advisor API calls. Running through this should give you a good idea of how Trsuted Advisor API works and how to get information you may need in enabling more checks with Trusted Advisor.

### 5.1 Trusted Advisor API Calls: Simmulating Initiate and Describe

The initiate function calls describe-trusted-advisor-checks, refresh-trusted-advisor-check, and describe-trusted-advisor-check-refresh-statuses. The describe function calls describe-trusted-advisor-check-result.

Simmulate it in the CLI with the following commands:

To gather all possible checks and their corresponding IDs:
```
$ aws support describe-trusted-advisor-checks --language en
```
To refresh a specific check's data:
```
$aws support refresh-trusted-advisor-check --check-id Qch7DwouX1
```
To check the refresh status of the check:
```
$ aws support describe-trusted-advisor-check-refresh-statuses --check-ids Qch7DwouX1
```
To get the official Trusted Advisor results of that check:
```
$ aws support describe-trusted-advisor-check-result --check-id Qch7DwouX1 --language en
```
## 6. Deployment in AWS Environment

For your referance, Any {UPPERCASE LETTERS} in brackets is a variable. Fill appropriately.

Make any applicable changes using above directions to deployment/configs/config.json

```
$ cd deployment
$ ./build_packages.sh configs/config.json
$ aws s3 sync packages/ {s3 bucket}
```

If you want to deploy through the cloudformation template, follow the below:

### 6.1 Execution Role in master account
This command creates the master role in the master account. This is the role that attaches to the Lambdas and is used to assume the role in member accounts.

```
aws cloudformation deploy --template-file identification-role.json --stack-name {STACKNAME} --parameter-overrides IdentificationIAMRole={MASTER ROLE} IdentificationCrossAccountIAMRole={CROSS ACCOUNT ROLE} ResourcesPrefix={RESOURCES PREFIX} --capabilities CAPABILITY_NAMED_IAM --region us-east-1
```
### 6.2 Create StackSet for cross account role

```
aws cloudformation create-stack-set --stack-set-name {STACK SET NAME} --template-body file://identification-crossaccount-role.json --administration-role-arn {ADMIN ROLE ARN} --execution-role-name {EXECUTION ROLE} --parameters {ANY PARAMS} --capabilities CAPABILITY_NAMED_IAM --region {REGION}
```
### 6.3 DynamoDB tables
This is a one-time command to initialize the ddb tables used in the master account.

```aws cloudformation deploy --template-file ddb.json --stack-name {STACK NAME} --parameter-overrides ResourcesPrefix={PREFIX} --region {REGION}
```
### 6.4 Identification Stack

```
aws cloudformation deploy --template-file identification.json --stack-name {STACKNAME} --parameter-overrides IdentificationIAMRole={MASTER ROLE} SourceS3Bucket={S3 BUCKET NAME} IdentificationCheckRateExpression="16 * * ? *" ResourcesPrefix={RESOURCES PREFIX} --s3-bucket {S3 BUCKET NAME} --s3-prefix {S3 PREFIX} --region {REGION}
```

### 6.5 Updating Lambda Code
To update lambda code, do all commands above to sync the s3 bucket and then run:

```
$ aws lambda update-function-code  --function function-name --s3-bucket {s3 bucket} --s3-key scanzipfile
```
An example of this, would be :
```
$ aws lambda update-function-code  --function dev-hammer-describe-ta-checks --{s3 bucket} --s3-key trusted-advisor-checks-identification.zip
```




