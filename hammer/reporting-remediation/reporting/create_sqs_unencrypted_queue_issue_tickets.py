"""
Class to create unencrypted SQS queue tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.aws.utility import Account
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, SQSEncryptionIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateSQSUnencryptedQueueIssueTickets:
    """ Class to create unencrypted SQS queue tickets """
    def __init__(self, config):
        self.config = config


    def create_tickets_sqs_unencrypted_queues(self):
        """ Class method to create jira tickets """
        table_name = self.config.sqsEncrypt.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, SQSEncryptionIssue)
            for issue in issues:
                queue_url = issue.issue_id
                queue_name = issue.issue_details.name
                queue_region = issue.issue_details.region
                tags = issue.issue_details.tags
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.issue_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} unencrypted SQS queue '{queue_name}' issue")

                        comment = (f"Closing {issue.status.value} unencrypted SQS queue '{queue_name}' "
                                   f"in '{account_name} / {account_id}' account, '{queue_region}' region")
                        jira.close_issue(
                            ticket_id=issue.jira_details.ticket,
                            comment=comment
                        )
                        slack.report_issue(
                            msg=f"{comment}"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_closed(ddb_table, issue)
                    # issue.status != IssueStatus.Closed (should be IssueStatus.Open)
                    elif issue.timestamps.updated > issue.timestamps.reported:
                        logging.debug(f"Updating unencrypted SQS queue '{queue_name}' issue")

                        comment = "Issue details are changed, please check again.\n"

                        comment += JiraOperations.build_tags_table(tags)
                        jira.update_issue(
                            ticket_id=issue.jira_details.ticket,
                            comment=comment
                        )
                        slack.report_issue(
                            msg=f"Unencrypted SQS queue '{queue_name}' issue is changed "
                                f"in '{account_name} / {account_id}' account, '{queue_region}' region"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_updated(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{queue_name}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting unencrypted SQS queue '{queue_name}' issue")

                    owner = tags.get("owner", None)
                    bu = tags.get("bu", None)
                    product = tags.get("product", None)

                    if bu is None:
                        bu = self.config.get_bu_by_name(queue_name)

                    issue_summary = (f"SQS unencrypted queue '{queue_name}' "
                                     f"in '{account_name} / {account_id}' account, '{queue_region}' region"
                                     f"{' [' + bu + ']' if bu else ''}")

                    issue_description = (
                        f"SQS Queue is unencrypted.\n\n"
                        f"*Threat*: "
                        f"Based on data protection policies, data that is classified as sensitive information or "
                        f"intellectual property of the organization needs to be encrypted. Additionally, as part of the "
                        f"initiative of Encryption Everywhere, it is necessary to encrypt the data in order to ensure the "
                        f"confidentiality and integrity of the data.\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*SQS queue url*: {queue_url}\n"
                        f"*SQS queue name*: {queue_name}\n"
                        f"*SQS queue region*: {queue_region}\n"
                        f"\n")

                    auto_remediation_date = (self.config.now + self.config.sqsEncrypt.issue_retention_date).date()
                    issue_description += f"\n{{color:red}}*Auto-Remediation Date*: {auto_remediation_date}{{color}}\n\n"

                    issue_description += JiraOperations.build_tags_table(tags)

                    issue_description += f"\n"
                    issue_description += (
                        f"*Recommendation*: "
                        f"Encrypt the Queue by enabling server-side encryption with AWS KMS-managed keys (SSE-KMS).")

                    if self.config.whitelisting_procedure_url:
                        issue_description += (f"For any other exceptions, please follow the [whitelisting procedure|{self.config.whitelisting_procedure_url}] "
                                              f"and provide a strong business reasoning. ")

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["sqs-unencrypted-queues"],
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                    except Exception:
                        logging.exception("Failed to create jira ticket")
                        continue

                    if response is not None:
                        issue.jira_details.ticket = response.ticket_id
                        issue.jira_details.ticket_assignee_id = response.ticket_assignee_id

                    issue.jira_details.owner = owner
                    issue.jira_details.business_unit = bu
                    issue.jira_details.product = product

                    slack.report_issue(
                        msg=f"Discovered {issue_summary}"
                            f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                        owner=owner,
                        account_id=account_id,
                        bu=bu, product=product,
                    )

                    IssueOperations.set_status_reported(ddb_table, issue)


if __name__ == '__main__':
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
        obj = CreateSQSUnencryptedQueueIssueTickets(config)
        obj.create_tickets_sqs_unencrypted_queues()
    except Exception:
        logging.exception("Failed to create unencrypted SQS queue tickets")
