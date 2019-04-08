---
title: Configuration and Deployment Overview
keywords: Configuration and Deployment Overview
sidebar: mydoc_sidebar
permalink: configuredeploy_overview.html
---

## 1. Introduction

This document describes how you can configure and deploy Dow Jones Hammer.

You can use [CloudFormation](https://aws.amazon.com/documentation/cloudformation/) or [Terraform](https://www.terraform.io/intro/index.html) to deploy Dow Jones Hammer. Choose the option that fits you best.

You should perform the following steps to configure and deploy Dow Jones Hammer:
1. Accomplish the [preliminary steps](#2-preliminary-steps).
2. Accomplish the steps specific to [CloudFormation](deployment_cloudformation.html) or [Terraform](deployment_terraform.html), depending on which option you have chosen.

## 2. Preliminary Steps

Both deployment scenarios share a number of preliminary steps you should accomplish before proceeding either with CloudFormation or Terraform deployment. This section contains the necessary details.

### 2.1. Clone Dow Jones Hammer Repository

To clone the Dow Jones Hammer repository, run the following commands:
```
git clone https://github.com/dowjones/hammer.git
cd hammer
```


### 2.2. Edit Dow Jones Hammer Configuration Files

Check [Dow Jones Hammer Configuration Files](editconfig.html) for details.


### 2.3. Build Dow Jones Hammer Packages

You should run `build_packages.sh` shell script from `deployment/` folder of Dow Jones Hammer sources on your local machine to build archives with Dow Jones Hammer packages. Use the main configuration file you edited on a previous step as script argument:

```
hammer $ cd deployment
hammer/deployment $ ./build_packages.sh configs/config.json
```

**Note**: `build_packages.sh` is tested to work with `bash` shell on `Linux` and `macOS`.
Also you should install following dependencies prior to script usage:
* `zip` (archiver for **.zip** files);
* [pip](https://pypi.org/project/pip/) (tool for installing Python packages).

### 2.4. Create S3 Buckets for Dow Jones Hammer

**Dow Jones Hammer Deployment Bucket**

You should create an S3 bucket in your master AWS account to upload archives with Dow Jones Hammer packages there. To do this, you can use the following AWS CLI command:
```
aws s3 mb s3://hammer-deploy-bucket
```
**Remediation Backup Bucket**

**Note**: this step is optional. Skip it if you do not intend to use remediation.

In case you intend to use remediation, you should configure an S3 bucket to enable remediation backup. To do this, you can use the following AWS CLI command:
```
aws s3 mb s3://hammer-backup-bucket

```


### 2.5. Create EC2 Key Pair for Dow Jones Hammer

**Note**: this step is optional. Continue with [deployment step](#3-deployment) in case you do not intend to use reporting/remediation or want to reuse existing key pair.

You should create an [EC2 key pair](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) to enable Dow Jones Hammer reporting/remediation functionality. To do this, proceed as follows:

1. Open the [Amazon EC2 console](https://console.aws.amazon.com/ec2/).
2. In the navigation pane on the left, under **NETWORK & SECURITY**, choose **Key Pairs**.
3. Choose **Create Key Pair**.
4. Enter a name for the new key pair in the **Key pair name** field of the **Create Key Pair** dialog box, and then choose **Create**.
5. Browser automatically downloads the private key file.


## 3. Deployment

### 3.1. Deployment with CloudFormation

In case you have chosen to deploy Dow Jones Hammer with CloudFormation, proceed as follows:
1. Make sure you have accomplished all of the [preliminary steps](#2-preliminary-steps).
2. Proceed to deploying Dow Jones Hammer with CloudFormation. Check [CloudFormation Deployment](deployment_cloudformation.html) for further guidance.


### 3.2. Deployment with Terraform

In case you have chosen to deploy Dow Jones Hammer with Terraform, proceed as follows:
1. Make sure you have accomplished all of the [preliminary steps](#2-preliminary-steps).
2. Proceed to deploying Dow Jones Dow Jones Hammer with Terraform. Check [Terraform Deployment](deployment_terraform.html) for further guidance.

### 3.3. Deployment of identification lambdas to VPC (optional)

It is not recommended, but you may **optionally** deploy identification lambdas to custom VPC instead of default system-managed VPC. To do so you may use [CloudFormation](deployment_cloudformation.html#313-identification-functionality)/[Terraform](deployment_terraform.html#32-the-variablestf-file) parameters for identification functionality.

Note well some requirements for such setup:
* you should specify both parameters (VPC subnets and security groups) simultaneously for Identification lambdas to be placed in your VPC. Or you can leave both parameters empty to place lambdas to system-managed VPC (default behavior)
* all subnets and security groups should be in the same VPC
* there should be enough free private IP addresses in subnets (at least 1 IP address for each enabled security feature) as for each lambda ENI is created
* subnets that you specify should be private subnets with default route attached to NAT gateway/instance, as lambdas need access to public endpoints (such as S3). It will not work if you try to place lambdas into public subnets with default route attached to Internet Gateway, as ENIs for lambdas do not have public IP by default and this can't be changed
* security groups should allow outbound connections

## 4. Concluding Steps

### 4.1. Access Credentials Storage

To configure:
* JIRA and/or Slack integration
* API token

you should inject corresponding access credentials to the credentials and values DynamoDB table, defined in `credentials` section of `config.json`.
Default table name is `hammer-credentials`.
Additionally, you can also specify API URL which will be used by slack bot for `scan account` operation

To inject the access credentials, run the script `ddb_inject_credentials.py` from the `hammer/tools/` folder:
```bash
hammer/tools $ export AWS_PROFILE=hammer-master
hammer/tools $ export AWS_DEFAULT_REGION="<hammer-master-region>"
hammer/tools $ python3.6 ddb_inject_credentials.py \
                            --table "<table name from config.json>" \
                            --hammer-api-token "<Hammer API token>" \
                            --hammer-api-url "<Hammer API URL>" \
                            --slack-api-token "<slack API token>" \
                            --jira-access-token-secret "<JIRA secret for access token>" \
                            --jira-access-token "<JIRA access token>" \
                            --jira-consumer-key "<JIRA consumer key>" \
                            --jira-key-cert-file "<path to the file with JIRA private key>"
```

In case operation was successful you should get output with injected credentials. Example:
```
Successfully injected 'slack' credentials: {
    "api_token": "<slack API token>"
}
Successfully injected 'api' credentials: {
    "token": "Hammer API token"
}
Successfully injected 'jira' credentials: {
    "oauth": {
        "consumer_key": "<JIRA consumer key>",
        "access_token": "<JIRA access token>",
        "key_cert": "-----BEGIN RSA PRIVATE KEY-----\n....-----END RSA PRIVATE KEY-----\n",
        "access_token_secret": "<JIRA secret for access token>"
    }
}
```

You can omit any of Slack, JIRA or API parameters in case you are not going to use corresponding integration functionality.

As for Hammer API token, you can provide your own randomly generated token or let script to generate it for you. To do so just omit value for `--hammer-api-token` parameter. 
