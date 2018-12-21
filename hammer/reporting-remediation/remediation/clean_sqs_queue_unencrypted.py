"""
Class to remediate SQS unencrypted queue.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import SQSEncryptionIssue
from library.aws.sqs import SQSEncryptionChecker
from library.aws.utility import Account
from library.utility import SingletonInstance, SingletonInstanceException


class CleanSQSUnencryptedQueue:
    """ Class to remediate SQS unencrypted queue """
    def __init__(self, config):
        self.config = config

    def clean_sqs_unencrypted_queue(self):
        """ Class method to clean SQS queues which are violating aws best practices """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.sqsEncrypt.ddb_table_name)

        retention_period = self.config.sqsEncrypt.remediation_retention_period
        remediation_warning_days = self.config.slack.remediation_warning_days

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, SQSEncryptionIssue)
            for issue in issues:
                queue_url = issue.issue_id
                queue_name = issue.issue_details.name
                queue_region = issue.issue_details.region

                in_whitelist = self.config.sqsEncrypt.in_whitelist(account_id, queue_url)

                if in_whitelist:
                    logging.debug(f"Skipping {queue_name} (in whitelist)")
                    continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{queue_name}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping {queue_name} (has been already remediated)")
                    continue

                updated_date = issue.timestamp_as_datetime
                no_of_days_issue_created = (self.config.now - updated_date).days

                owner = issue.jira_details.owner
                bu = issue.jira_details.business_unit
                product = issue.jira_details.product

                issue_remediation_days = retention_period - no_of_days_issue_created
                if issue_remediation_days in remediation_warning_days:
                    slack.report_issue(
                        msg=f"SQS SQS unencrypted Queue '{queue_name}' issue is going to be remediated in "
                            f"{issue_remediation_days} days",
                        owner=owner,
                        account_id=account_id,
                        bu=bu, product=product,
                    )
                elif no_of_days_issue_created >= retention_period:
                    try:
                        account = Account(id=account_id,
                                          name=account_name,
                                          region=issue.issue_details.region,
                                          role_name=self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        checker = SQSEncryptionChecker(account=account)
                        checker.check(queues=[queue_url])
                        queue = checker.get_queue(queue_name)
                        if queue is None:
                            logging.debug(f"Queue {queue_name} was removed by user")
                        elif not queue.encrypted:
                            logging.debug(f"Queue {queue.name} unencrypted issue was remediated by user")
                        else:
                            logging.debug(f"Remediating unencrypted '{queue.name}' ")
                            kms_key_id = None
                            remediation_succeed = True
                            if queue.encrypt_queue(kms_key_id):
                                comment = (f"Queue '{queue.name}' unencrypted issue "
                                           f"in '{account_name} / {account_id}' account, '{queue_region}' region "
                                           f"was remediated by hammer")
                            else:
                                remediation_succeed = False
                                comment = (f"Failed to remediate queue '{queue.name}' unencrypted issue "
                                           f"in '{account_name} / {account_id}' account, '{queue_region}' region "
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
                        logging.exception(f"Error occurred while updating queue '{queue_url}' unencrypted issue "
                                          f"in '{account_name} / {account_id}', '{queue_region}' region")
                else:
                    logging.debug(f"Skipping '{queue_name}' "
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

    try:
        class_object = CleanSQSUnencryptedQueue(config)
        class_object.clean_sqs_unencrypted_queue()
    except Exception:
        logging.exception("Failed to clean SQS queue unencrypted issue")