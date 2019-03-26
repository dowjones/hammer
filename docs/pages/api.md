---
title: API Usage
sidebar: mydoc_sidebar
permalink: api.html
---

## 1. Preliminary Steps

You can use Dow Jones Hammer REST API to perform ad-hoc scans of controlled environments. To use it you need to:
* deploy [CloudFormation API functionality](deployment_cloudformation.html#316-api-functionality) or ensure that [Terraform API module](deployment_terraform.html#3-edit-terraform-configuration-files) is included in `terraform.tf`
* note down **ApiUrl** output variable of [Terraform](deployment_terraform.html#5-check-terraform-output-variables) / [CloudFormation API stack](deployment_cloudformation.html#3-deploy-cloudformation-stacks-to-the-master-aws-account)
* [inject](configuredeploy_overview.html#41-access-credentials-storage) Dow Jones Hammer API token and Dow Jones Hammer API URL (optional, if you are going to use slack bot for scanning) to credentials DynamoDB table

## 2. Request

Use `curl` or any other tool for making HTTP queries. You need to perform POST request to **ApiUrl** and provide:
* API token in `Auth` header
* JSON payload as a POST data
* (optional) set `application/json` content type.

Request example:
```
$ curl -H 'Auth: ieng4aechooth4Ahzou2beeg8phohz' \
       -H 'Content-Type: application/json' \
       https://boafxucxrw.execute-api.eu-west-1.amazonaws.com/LATEST/identify \
       -d '
{
    "account_id": "1234567890"
}'
       
```

JSON payload should include:
* **account_id**: controlled AWS account ID to check. It must be account ID from the `aws.accounts` [configuration option](editconfig.html#11-master-aws-account-settings)
* (optional) **security_features**: the list of security feature names to scan. These names should be the same as configuration section names for each supported security feature (f.e. - `secgrp_unrestricted_access`, `user_inactivekeys`, `s3_bucket_policy`, etc).
If omitted, all supported features will be checked 
* (optional) **regions**: for regional services, such as security groups, EBS/RDS snapshots, etc, you need to provide list of regions to check issues in. If it is omitted, all regions will be checked
* (optional) **tags**: dictionary with tags to limit checks by tags attached to resources


Request example of checking public EBS snapshots and unrestricted security groups only for resources tagged with `prod` for `accounting` and `staffing` business units in us-east-2 and us-east-1 regions:
```

$ curl -X POST -H 'Auth: ieng4aechooth4Ahzou2beeg8phohz' \
               -H 'Content-Type: application/json' \
               https://boafxucxrw.execute-api.us-east-1.amazonaws.com/LATEST/identify -d '
{
    "account_id": "1234567890",
    "regions": ["us-east-1", "us-east-2"],
    "security_features": ["s3_bucket_acl", "secgrp_unrestricted_access"],
    "tags": {
        "bu": ["accounting", "staffing"],
        "env": "prod"
    }
}'
```
This operation is asynchronous and returns `request_id` which can be used then to retrieve results of scan.
Response may look like this:
```
{
    "request_id": "d9ad40e4f59b4424b6ba995aa85de40e"
}

```
Another request should be issued to retrieve results:
```
curl -H "Auth: ieng4aechooth4Ahzou2beeg8phohz" \
     -H 'Content-Type: application/json' \
     https://boafxucxrw.execute-api.us-east-1.amazonaws.com/LATEST/identify/d9ad40e4f59b4424b6ba995aa85de40e

```
This request may return such result:
```
{
    "scan_status": "IN_PROGRESS"
}
```
Which means the scan is still in progress. Eventually the scan will be finished and response with results od scan will be returned.

## 3. Response

Dow Jones Hammer API returns responses in JSON format. If scan was successful it returns scan result in the key `scan_results` and `scan_status` that is equal to `COMPLETE`.

This is how response may look like:
```
{
    "scan_status": "COMPLETE",
    "scan_results": {
        "global": {
            "s3_bucket_policy": [],
            "s3_bucket_acl": [],
            "user_inactivekeys": [],
            "user_keysrotation": []
        },
        "us-east-1": {
            "secgrp_unrestricted_access": [
                {
                    "id": "sg-002f6eaff01234567",
                    "issue_details": {
                        "name": "rds-launch-wizard-2",
                        "perms": [
                            {
                                "to_port": 3306,
                                "protocol": "tcp",
                                "cidr": "4.5.6.107/32",
                                "from_port": 3306,
                                "status": "open_partly"
                            }
                        ],
                        "region": "us-east-1",
                        "tags": {},
                        "status": "open_partly"
                    }
                },
            ],
            "ebs_public_snapshot": [],
            "rds_public_snapshot": [],
            "sqs_public_access": []
        },
    }
}
```
