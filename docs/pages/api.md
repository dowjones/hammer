---
title: API Usage
sidebar: mydoc_sidebar
permalink: api.html
---

## 1. Preliminary Steps

You can use Dow Jones Hammer REST API to perform ad-hoc scans of controlled environments. To use it you need to:
* deploy [CloudFormation API functionality](deployment_cloudformation.html#316-api-functionality) or ensure that [Terraform API module](deployment_terraform.html#3-edit-terraform-configuration-files) is included in `terraform.tf`
* note down **ApiUrl** output variable of [Terraform](deployment_terraform.html#5-check-terraform-output-variables) / [CloudFormation API stack](deployment_cloudformation.html#3-deploy-cloudformation-stacks-to-the-master-aws-account)
* [inject](configuredeploy_overview.html#41-access-credentials-storage) Dow Jones Hammer API token to credentials DynamoDB table

## 2. Request

Use `curl` or any other tool for making HTTP queries. You need to perform POST request to **ApiUrl** and provide:
* API token in `Auth` header
* JSON payload as a POST data
* (optional) set `application/json` content type.

Request example:
```
$ curl -H 'Auth: ieng4aechooth4Ahzou2beeg8phohz' \
       -H 'Content-Type: application/json' \
       https://boafxucxrw.execute-api.eu-west-1.amazonaws.com/LATEST/scan \
       -d '
{
    "account_id": "1234567890",
    "region": "us-east-1",
    "security_feature": "secgrp_unrestricted_access"
}'
       
```

JSON payload should include:
* **account_id**: controlled AWS account ID to check. It must be account ID from the `aws.accounts` [configuration option](editconfig.html#11-master-aws-account-settings)
* **security_feature**: the name of the security feature to scan. This name should be the same as configuration section name for each supported security feature (f.e. - `secgrp_unrestricted_access`, `user_inactivekeys`, `s3_bucket_policy`, etc) 
* (optional) **region**: for regional services, such as security groups, EBS/RDS snapshots, etc, you need to provide region to check issues in. If it is omitted, the default region (where Dow Jones Hammer was deployed) will be checked
* (optional) **tags**: dictionary with tags to limit checks by tags attached to resources
* (optional) **ids**: list with resource ids to limit checks


Request example of checking two S3 buckets public ACLs:
```
$ curl -H 'Auth: ieng4aechooth4Ahzou2beeg8phohz' \
       -H 'Content-Type: application/json' \
       https://boafxucxrw.execute-api.eu-west-1.amazonaws.com/LATEST/scan \
       -d '
{
    "account_id": "1234567890",
    "region": "us-east-1",
    "security_feature": "s3_bucket_acl",
    "ids": [
        "BucketName1",
        "BucketName2"
    ]
}'
```

Request example of checking public EBS snapshots only for resources tagged with `prod` for `accounting` and `staffing` business units:
```
$ curl -H 'Auth: ieng4aechooth4Ahzou2beeg8phohz' \
       -H 'Content-Type: application/json' \
       https://boafxucxrw.execute-api.eu-west-1.amazonaws.com/LATEST/scan \
       -d '
{
    "account_id": "1234567890",
    "region": "us-east-1",
    "security_feature": "s3_bucket_acl",
    "tags": {
        "bu": ["accounting", "staffing"],
        "env": "prod"
    }
}'
```

## 3. Response

Dow Jones Hammer API returns responses in JSON format. If scan was successful it returns scan result in the key with the security feature name (as it was in `security_feature` request parameter).

Insecure services response example:
```
{
    "secgrp_unrestricted_access": [
        {
            "id": "sg-123456",
            "name": "ssh-test1",
            "status": "open_partly",
            "permissions": [
                {
                    "ports": "22",
                    "protocol": "tcp",
                    "cidr": "1.1.1.1/32"
                }
            ]
        },
        {
            "id": "sg-654321",
            "name": "ssh-test2",
            "status": "open_completely",
            "permissions": [
                {
                    "ports": "22",
                    "protocol": "tcp",
                    "cidr": "0.0.0.0/0"
                }
            ]
        }
    ]
}
```

S3 bucket ACL response example:
```
{
    "s3_bucket_acl": [
        {
            "name": "test-bucket",
            "public_acls": {
                "AllUsers": [
                    "READ",
                    "READ_ACP"
                ]
            }
        }
    ]
}
```