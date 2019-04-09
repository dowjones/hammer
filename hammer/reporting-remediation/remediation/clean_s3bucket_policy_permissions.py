"""
Class to remediate S3 bucket policy permissions.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import IssueStatus, S3PolicyIssue
from library.aws.s3 import S3BucketsPolicyChecker
from library.aws.utility import Account
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanS3BucketPolicyPermissions:
    """ Class to remediate S3 bucket policy permissions """
    def __init__(self, config):
        self.config = config

    def clean_s3bucket_policy_permissions(self, batch=False):
        """ Class method to clean S3 buckets which are violating aws best practices """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.s3policy.ddb_table_name)
        backup_bucket = config.aws.s3_backup_bucket

        retention_period = self.config.s3policy.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.s3policy.remediation_accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, S3PolicyIssue)
            for issue in issues:
                bucket_name = issue.issue_id

                in_whitelist = self.config.s3policy.in_whitelist(account_id, bucket_name)
                #in_fixlist = self.config.s3policy.in_fixnow(account_id, bucket_name)

                if in_whitelist:
                    logging.debug(f"Skipping {bucket_name} (in whitelist)")

                    # Adding label with "whitelisted" to jira ticket.
                    jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        label=IssueStatus.Whitelisted.value
                    )
                    continue
                # if not in_fixlist:
                #     logging.debug(f"Skipping {bucket_name} (not in fixlist)")
                #     continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{bucket_name}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping {bucket_name} (has been already remediated)")
                    continue

                updated_date = issue.timestamp_as_datetime
                no_of_days_issue_created = (self.config.now - updated_date).days

                if no_of_days_issue_created >= retention_period:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    try:
                        account = Account(id=account_id,
                                          name=account_name,
                                          role_name=self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        checker = S3BucketsPolicyChecker(account=account)
                        checker.check(buckets=[bucket_name])
                        s3bucket = checker.get_bucket(bucket_name)
                        if s3bucket is None:
                            logging.debug(f"Bucket {s3bucket.name} was removed by user")
                        elif not s3bucket.public_by_policy:
                            logging.debug(f"Bucket {s3bucket.name} policy issue was remediated by user")
                        else:
                            if not batch and \
                               not confirm(f"Do you want to remediate '{bucket_name}' S3 bucket policy", False):
                                continue

                            logging.debug(f"Remediating '{s3bucket.name}' policy")

                            backup_path = s3bucket.backup_policy_s3(main_account.client("s3"), backup_bucket)
                            remediation_succeed = True
                            if s3bucket.restrict_policy():
                                comment = (f"Policy backup was saved to "
                                           f"[{backup_path}|https://s3.console.aws.amazon.com/s3/object/{backup_bucket}/{backup_path}]. "
                                           f"Bucket '{s3bucket.name}' policy issue "
                                           f"in '{account_name} / {account_id}' account "
                                           f"was remediated by hammer")
                            else:
                                remediation_succeed = False
                                comment = (f"Failed to remediate bucket '{s3bucket.name}' policy issue "
                                           f"in '{account_name} / {account_id}' account "
                                           f"due to some limitations. Please, check manually")

                            jira.remediate_issue(
                                ticket_id=issue.jira_details.ticket,
                                comment=comment,
                                reassign=remediation_succeed,
                            )
                            slack.report_issue(
                                msg=f"{comment}"
                                    f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                                owner=owner,
                                account_id=account_id,
                                bu=bu, product=product,
                            )
                            IssueOperations.set_status_remediated(ddb_table, issue)
                    except Exception:
                        logging.exception(f"Error occurred while updating bucket '{bucket_name}' policy "
                                          f"in '{account_name} / {account_id}'")
                else:
                    logging.debug(f"Skipping '{bucket_name}' "
                                  f"({retention_period - no_of_days_issue_created} days before remediation)")


if __name__ == "__main__":
    module_name = sys.modules[__name__].__loader__.name
    set_logging(level=logging.DEBUG, logfile=f"/var/log/hammer/{module_name}.log")
    config = Config()
    add_cw_logging(config.local.log_group,
                   log_stream=module_name,
                   level=logging.DEBUG,
                   region=config.aws.region)
    try:
        si = SingletonInstance(module_name)
    except SingletonInstanceException:
        logging.error(f"Another instance of '{module_name}' is already running, quitting")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('--batch', action='store_true', help='Do not ask confirmation for remediation')
    args = parser.parse_args()

    try:
        class_object = CleanS3BucketPolicyPermissions(config)
        class_object.clean_s3bucket_policy_permissions(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean S3 public policies")
