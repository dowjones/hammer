"""
Class method to create JIRA tickets and update dynamo db table.
"""
import sys
import logging
import dateutil.parser


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.aws.utility import Account
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, IAMKeyInactiveIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateTicketIamInactiveKeys:
    """ Class method to update dynamo db table """
    def __init__(self, config):
        self.config = config

    def create_jira_ticket(self):
        """ Class method to create jira ticket """
        table_name = self.config.iamUserInactiveKeys.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.iamUserInactiveKeys.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, IAMKeyInactiveIssue)
            for issue in issues:
                key_id = issue.issue_id
                username = issue.issue_details.username
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} inactive access key '{key_id} / {username}' issue")

                        comment = (f"Closing {issue.status.value} inactive access key '{key_id} / {username}' issue "
                                   f"in '{account_name} / {account_id}' account")
                        if issue.status == IssueStatus.Whitelisted:
                            # Adding label with "whitelisted" to jira ticket.
                            jira.add_label(
                                ticket_id=issue.jira_details.ticket,
                                label=IssueStatus.Whitelisted.value
                            )
                        jira.close_issue(
                            ticket_id=issue.jira_details.ticket,
                            comment=comment
                        )
                        slack.report_issue(
                            msg=f"{comment}"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            account_id=account_id,
                        )
                        IssueOperations.set_status_closed(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{key_id} / {username}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting inactive access key '{key_id} / {username}' issue")

                    issue_summary = (f"IAM access key '{key_id}' for '{username}' has not been used "
                                     f"for {self.config.iamUserInactiveKeys.inactive_criteria_days.days} days "
                                     f"in '{account_name} / {account_id}' account")

                    create_date = dateutil.parser.parse(issue.issue_details.create_date).replace(tzinfo=None).isoformat(' ', 'minutes')
                    last_used = dateutil.parser.parse(issue.issue_details.last_used).replace(tzinfo=None).isoformat(' ', 'minutes')
                    issue_description = (
                        f"IAM access key has not been used for {self.config.iamUserInactiveKeys.inactive_criteria_days.days} days.\n\n"
                        f"*Risk*: Low\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*User Name*: {username}\n"
                        f"*Key ID*: {key_id}\n"
                        f"*Key created*: {create_date}\n"
                        f"*Key last used*: {last_used}\n"
                        f"\n")

                    auto_remediation_date = (self.config.now + self.config.iamUserInactiveKeys.issue_retention_date).date()
                    issue_description += f"\n{{color:red}}*Auto-Remediation Date*: {auto_remediation_date}{{color}}\n\n"

                    issue_description += f"*Recommendation*: Deactivate specified inactive user access key. "

                    if self.config.whitelisting_procedure_url:
                        issue_description += (f"For any other exceptions, please follow the [whitelisting procedure|{self.config.whitelisting_procedure_url}] "
                                              f"and provide a strong business reasoning. ")

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["inactive-iam-keys"],
                            account_id=account_id,
                        )
                    except Exception:
                        logging.exception("Failed to create jira ticket")
                        continue

                    if response is not None:
                        issue.jira_details.ticket = response.ticket_id
                        issue.jira_details.ticket_assignee_id = response.ticket_assignee_id

                    slack.report_issue(
                        msg=f"Discovered {issue_summary}"
                            f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                        account_id=account_id,
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
        obj = CreateTicketIamInactiveKeys(config)
        obj.create_jira_ticket()
    except Exception:
        logging.exception("Failed to create IAM user keys inactive tickets")
