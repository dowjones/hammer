![HammerLogo](docs/images/dow-jones-hammer-logo.png)

## Overview

Dow Jones Hammer is a multi-account cloud security tool for AWS. It identifies misconfigurations and insecure data exposures within most popular AWS resources, across all regions and accounts. It has near real-time reporting capabilities (e.g. JIRA, Slack) to provide quick feedback to engineers and can perform auto-remediation of some misconfigurations. This helps to protect products deployed on cloud by creating secure guardrails.

![HammerLifecycleDiagram](docs/images/Architecture.png)

## Documentation
Dow Jones Hammer documentation is available via GitHub Pages at [https://dowjones.github.io/hammer/](https://dowjones.github.io/hammer/).

## Security features
* [Insecure Services](https://dowjones.github.io/hammer/playbook2_insecure_services.html)
* [S3 ACL Public Access](https://dowjones.github.io/hammer/playbook1_s3_public_buckets_acl.html)
* [S3 Policy Public Access](https://dowjones.github.io/hammer/playbook5_s3_public_buckets_policy.html)
* [IAM User Inactive Keys](https://dowjones.github.io/hammer/playbook3_inactive_user_keys.html)
* [IAM User Keys Rotation](https://dowjones.github.io/hammer/playbook4_keysrotation.html)
* [CloudTrail Logging Issues](https://dowjones.github.io/hammer/playbook6_cloudtrail.html)
* [EBS Unencrypted Volumes](https://dowjones.github.io/hammer/playbook7_ebs_unencrypted_volumes.html)
* [EBS Public Snapshots](https://dowjones.github.io/hammer/playbook8_ebs_snapshots_public.html)
* [RDS Public Snapshots](https://dowjones.github.io/hammer/playbook9_rds_snapshots_public.html)
* [SQS Public Policy Access](https://dowjones.github.io/hammer/playbook10_sqs_public_policy.html)
* [S3 Unencrypted Buckets](https://dowjones.github.io/hammer/playbook11_s3_unencryption.html)
* [RDS Unencrypted Instances](https://dowjones.github.io/hammer/playbook12_rds_unencryption.html)
* [AMIs Public Access](https://dowjones.github.io/hammer/playbook13_amis_public_access.html)
* [Redshift Unencrypted Clusters](https://dowjones.github.io/hammer/playbook15_redshift_unencryption.html)
* [Redshift Public Clusters](https://dowjones.github.io/hammer/playbook16_redshift_public_clusters.html)
* [Redshift Logging Issues](https://dowjones.github.io/hammer/playbook17_redshift_audit_logging.html)
* [ECS Logging Issues](https://dowjones.github.io/hammer/playbook18_ecs_logging.html)
* [ECS Privileged Access Issues](https://dowjones.github.io/hammer/playbook19_ecs_privileged_access.html)
* [ECS Exteranal Image Source Issues](https://dowjones.github.io/hammer/playbook20_ecs_external_image_source.html)
* [Elasticsearch Unencrypted Domains](https://dowjones.github.io/hammer/playbook21_elasticsearch_unencryption.html)
* [Elasticsearch Public Domains](https://dowjones.github.io/hammer/playbook22_elasticsearch_public_access.html)
* [Elasticsearch Logging Issues](https://dowjones.github.io/hammer/playbook23_elasticsearch_logging.html)

## Technologies
* Python 3.6
* AWS (Lambda, Dynamodb, EC2, SNS, CloudWatch, CloudFormation)
* Terraform
* JIRA
* Slack

## Contributing

You are welcome to contribute!

### Issues:

You can use [GitHub Issues](https://github.com/dowjones/hammer/issues) to report issues.
Describe what is going on wrong and what you expect to be correct behaviour.

### Patches:

We currently use [dev](https://github.com/dowjones/hammer/tree/dev) branch for ongoing development. Please open
PRs to this branch.

### Run tests:

Run tests with this command:
```shell
tox
```


## Contact Us
Feel free to create [issue report](https://github.com/dowjones/hammer/issues/new), pull request or just email us at [hammer@dowjones.com](mailto:hammer@dowjones.com) with any other questions or concerns you have.
