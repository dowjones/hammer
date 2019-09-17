---
title: RDS unencrypted instances
keywords: playbook12
sidebar: mydoc_sidebar
permalink: playbook12_rds_unencryption.html
---

# Playbook 25: Adding Your own Rule to Hammer

## Introduction
The purpose of this document is to give an overview of the relevant files needed in the process of adding new checks to Hammer. The file changes outlined below are not necessarily in any specific order. The files may need to be revisited throughout the process as you add specifications. There may be more steps and file changes for your specific rule you are adding. Let this be a general guide to help get you started on integrating your new checks with Hammer!

Hammer uses a nested stack model for deploying cloud formation templates.


## 1. Files
The following are files that will likely need to be updated for your specific rule. Read on to see what each means and how to update!

deployment/build_packages.sh
deployment/cf-templates/ddb.json
deployment/cf-templates/identification-crossaccount-role.json
deployment/cf-templates/Identification-role.json
deployment/cf-templates/Identification.json
deployment/configs/config.json
hammer/identification/lambdas/
hammer/identification/lambdas/metrics-publisher/metrics_publisher.py
hammer/library/aws/
hammer/library/config.py
hammer/library/ddb_issues.py


## 2. Main Changes


1. Add DynamoDB information to ***deployment/cf-templates/ddb.json***

- Update the reference name of the table
- “Key Schema”
Must make the attributes account_id and issue_id
- “BillingMode”: “PAY_PER_REQUEST”
On demand payment makes more sense with how we are currently using the dynamo tables
- “TableName”:
Specify your table name,which will follow the resources prefix

2. Update ***deployment/cf-templates/identification-crossaccount-role.json***

- This is the template for the CrossAcccount Role
- Holds the permissions and policies for HammerCrossAccountIdentifyRole
- CrossAccountRoles are assumed by the master account for permissions in slave accounts
- Change any policies/permissions as required
- Head to https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html, and find “JSON Policy Document Structure” to understand how to update your policies by adding a statement


3. Update ***deployment/cf-templates/Identification-role.json***

- This is the Master Role Cloud Formation template.
- Holds the permissions and policies for HammerMasterIdentifyRole
- This is the Master Role that all lambdas assume
- Update policies/permissions as needed


4. Update ***deployment/cf-templates/Identification.json***

- Identification stack for Hammer
- Nested Stack Template
- Add your rule’s Cloud Formation Stack following the conventions of previous stacks

5. Add your rules configuration specifications to ***deployment/configs/config.json***

6. Update config parser ***hammer/library/config.py***

- utility functions to parse a rule’s specific config specifications
- Enable lambda to read config file you pass for your specific rule
- Can extend ModuleConfig or use ModuleConfig if your specific check config doesn’t have any extra properties to be accessed

7. Add your lambda functions to ***hammer/identification/lambdas/***

- Create a folder for your rule and add all necessary lambda.py files : the initiate and describe functions.

8. Add ddb name to ***hammer/identification/lambdas/metrics-publisher/metrics_publisher.py***

- Configure with ddb table name to publish metrics

9. Add function methods to your specific check’s util file (create one if applicable) in ***hammer/library/aws/***

- Parent folder that holds all rule’s utility functions.
- Add logic to the Checker class, which checks the status of resources in AWS environ
- EXAMPLE) hammer/library/aws/ta.py holds the trusted advisor helper functions including Checker class

10. Update ***hammer/library/ddb_issues.py***
- Add your specific rule Issue Class
- May need to provide it specific functionality depending on your rule

11. Add lambda folder name to ***deployment/build_packages.sh***
- Under LAMBDAS variable, add the name of the folder for your new rule. This is the folder that will be zipped and deployed.


