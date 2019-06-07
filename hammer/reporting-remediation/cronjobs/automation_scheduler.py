"""
Cron jobs for remediation automation.
"""
import os
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config


class CronJobs(object):
    def __init__(self, title):
        self.title = title
        self.jobs = []
        self.cron_path = "/etc/cron.d"
        self.user = "root"

    def add(self, schedule, command):
        self.jobs.append(f"{schedule}\t{self.user}\t{command}")

    def save(self):
        with open(os.path.join(self.cron_path, self.title), "wt") as fh:
            for job in self.jobs:
                fh.write(f"{job}\n")


def automation_cronjob(config):
    reporting_schedule = config.cronjobs["reporting"]
    remediation_schedule = config.cronjobs["remediation"]
    csv_reporting_schedule = config.csv.schedule

    logging.debug("Adding hammer crontab tasks")

    reporting_jobs = CronJobs("hammer-reporting")
    remediation_jobs = CronJobs("hammer-remediation")

    if config.csv.enabled:
        logging.debug(f"Adding CSV reporting with '{csv_reporting_schedule}' schedule")
        reporting_jobs.add(
            schedule=csv_reporting_schedule,
            command='cd /hammer-correlation-engine && python3.6 -m analytics.security_issues_csv_report'
        )

    modules = [
        ("S3 ACL Public Access",      config.s3acl,               "create_s3bucket_acl_issue_tickets",    "clean_s3bucket_acl_permissions"),
        ("Insecure Services",         config.sg,                  "create_security_groups_tickets",       "clean_security_groups"),
        ("IAM User Inactive Keys",    config.iamUserInactiveKeys, "create_iam_key_inactive_tickets",      "clean_iam_keys_inactive"),
        ("IAM User Key Rotation",     config.iamUserKeysRotation, "create_iam_key_rotation_tickets",      "clean_iam_key_rotation"),
        ("S3 Policy Public Access",   config.s3policy,            "create_s3bucket_policy_issue_tickets", "clean_s3bucket_policy_permissions"),
        ("CloudTrail Logging Issues", config.cloudtrails,         "create_cloudtrail_tickets",            None),
        ("EBS Unencrypted Volumes",   config.ebsVolume,           "create_ebs_volume_issue_tickets",      None),
        ("EBS Public Snapshots",      config.ebsSnapshot,         "create_ebs_public_snapshot_issue_tickets", "clean_public_ebs_snapshots"),
        ("RDS Public Snapshots",      config.rdsSnapshot,         "create_rds_public_snapshot_issue_tickets", "clean_public_rds_snapshots"),
        ("EC2 Public Images",         config.publicAMIs,          "create_public_ami_issue_tickets",      "clean_ami_public_access"),
        ("SQS Public Access",         config.sqspolicy,           "create_sqs_policy_issue_tickets",          "clean_sqs_policy_permissions"),
        ("S3 Unencrypted Buckets",    config.s3Encrypt,           "create_s3_unencrypted_bucket_issue_tickets", "clean_s3bucket_unencrypted"),
        ("RDS Unencrypted Instances", config.rdsEncrypt,          "create_rds_unencrypted_instance_issue_tickets", None),
    ]

    for title, module_config, reporting_script, remediation_script in modules:
        if module_config.reporting and reporting_script is not None:
            logging.debug(f"Adding {title} reporting with '{reporting_schedule}' schedule")
            reporting_jobs.add(
                schedule=reporting_schedule,
                command=f'cd /hammer-correlation-engine && python3.6 -m reporting.{reporting_script}',
            )

        if module_config.remediation and remediation_script is not None:
            logging.debug(f"Adding {title} remediation with '{remediation_schedule}' schedule")
            remediation_jobs.add(
                schedule=remediation_schedule,
                command=f'cd /hammer-correlation-engine && python3.6 -m remediation.{remediation_script} --batch',
            )

    reporting_jobs.save()
    remediation_jobs.save()


if __name__ == '__main__':
    module_name = sys.modules[__name__].__loader__.name
    set_logging(level=logging.DEBUG, logfile=f"/var/log/hammer/{module_name}.log")
    config = Config()
    add_cw_logging(config.local.log_group,
                   log_stream=module_name,
                   level=logging.DEBUG,
                   region=config.aws.region)

    automation_cronjob(config)
