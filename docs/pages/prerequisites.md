---
title: Prerequisites
keywords: Prerequisites
sidebar: mydoc_sidebar
permalink: prerequisites.html
---

This section describes steps that you should take before proceeding to Dow Jones Hammer configuration and deployment.


## 1. Amazon Web Services Command Line Interface Setup

To make Dow Jones Hammer configuration more convenient, you should install AWS Command Line Interface (CLI) - a unified tool to manage your AWS services. With just one tool to download and configure, you can control multiple AWS services from the command line and automate them through scripts.

You will be using AWS CLI tools to perform the following tasks related to Dow Jones Hammer setup:
* S3 Bucket creation
* Lambda packages upload

Check AWS CLI documentation for further details: [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/).

## 2. Access Rights for Amazon Products

This section describes the following two sets of AWS access rights:
* access rights required to deploy Dow Jones Hammer
* access rights required to run Dow Jones Hammer

### 2.1. Dow Jones Hammer Deployment

To deploy Dow Jones Hammer, you have to have administrator access rights for your master AWS account and slave AWS accounts.

**Note**: During the Dow Jones Hammer Deployment a DynamoDB table for Slack and/or JIRA credentials will be created. To keep this data secure, the table will be [encrypted at rest](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html).

### 2.2. Dow Jones Hammer Operation

**Identification** / **Reporting**

Dow Jones Hammer needs following access rights to perform issues identification and reporting:
1. Master Account:
    * Read-write access to CloudWatch and DynamoDB.
    * Read-only access to AWS services for which you have enabled issue identification.
2. Slave Accounts:
    * Read-only access to the AWS services for which you have enabled issue identification.

**Remediation**

In case you have configured Dow Jones Hammer to perform issue reporting, Dow Jones Hammer needs following access rights:
1. Master Account:
    * Read-write access to CloudWatch, DynamoDB and AWS services for which you have enabled remediation.
    * Read-only access to other AWS services for which you have *not* enabled issue remediation.
2. Slave Accounts:
    * Read-write access to AWS services for which you have enabled remediation.
    * Read-only access to other AWS services for which you have *not* enabled issue remediation.
