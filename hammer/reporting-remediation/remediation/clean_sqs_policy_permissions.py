"""
Class to remediate SQS policy permissions.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import IssueStatus, SQSPolicyIssue
from library.aws.sqs import SQSPolicyChecker
from library.aws.utility import Account
from library.utility import SingletonInstance, SingletonInstanceException


class CleanSQSPolicyPermissions:
    """ Class to remediate SQS policy permissions """
    def __init__(self, config):
        self.config = config

    def clean_sqs_policy_permissions(self):
        """ Class method to clean SQS queues which are violating aws best practices """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.sqspolicy.ddb_table_name)
        backup_bucket = config.aws.s3_backup_bucket

        retention_period = self.config.sqspolicy.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, SQSPolicyIssue)
            for issue in issues:
                queue_url = issue.issue_id
                queue_name = issue.issue_details.name
                queue_region = issue.issue_details.region

                in_whitelist = self.config.sqspolicy.in_whitelist(account_id, queue_url)

                if in_whitelist:
                    logging.debug(f"Skipping {queue_name} (in whitelist)")

                    # Adding label with "whitelisted" to jira ticket.
                    jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        label=IssueStatus.Whitelisted.value
                    )
                    continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{queue_name}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping {queue_name} (has been already remediated)")
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
                                          region=issue.issue_details.region,
                                          role_name=self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        checker = SQSPolicyChecker(account=account)
                        checker.check(queues=[queue_url])
                        queue = checker.get_queue(queue_name)
                        if queue is None:
                            logging.debug(f"Queue {queue_name} was removed by user")
                        elif not queue.public:
                            logging.debug(f"Queue {queue.name} policy issue was remediated by user")
                        else:
                            logging.debug(f"Remediating '{queue.name}' policy")

                            backup_path = queue.backup_policy_s3(main_account.client("s3"), backup_bucket)
                            remediation_succeed = True
                            if queue.restrict_policy():
                                comment = (f"Policy backup was saved to "
                                           f"[{backup_path}|https://s3.console.aws.amazon.com/s3/object/{backup_bucket}/{backup_path}]. "
                                           f"Queue '{queue.name}' policy issue "
                                           f"in '{account_name} / {account_id}' account, '{queue_region}' region "
                                           f"was remediated by hammer")
                            else:
                                remediation_succeed = False
                                comment = (f"Failed to remediate queue '{queue.name}' policy issue "
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
                        logging.exception(f"Error occurred while updating queue '{queue_url}' policy "
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
        class_object = CleanSQSPolicyPermissions(config)
        class_object.clean_sqs_policy_permissions()
    except Exception:
        logging.exception("Failed to clean SQS queue public policies")