"""
Class to create redshift unencrypted cluster issue tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.aws.utility import Account
from library.config import Config
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, RedshiftEncryptionIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateRedshiftUnencryptedInstanceTickets(object):
    """ Class to create redshift unencrypted cluster issue issue tickets """
    def __init__(self, config):
        self.config = config

    def create_tickets_redshift_unencrypted_cluster(self):
        """ Class method to create jira tickets """
        table_name = self.config.redshiftEncrypt.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, RedshiftEncryptionIssue)
            for issue in issues:
                cluster_id = issue.issue_id
                region = issue.issue_details.region
                tags = issue.issue_details.tags
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} Redshift unencrypted cluster  '{cluster_id}' issue")

                        comment = (f"Closing {issue.status.value} Redshift unencrypted cluster '{cluster_id}' issue "
                                   f"in '{account_name} / {account_id}' account, '{region}' region")
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
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_closed(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{cluster_id}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting Redshift unencrypted cluster '{cluster_id}' issue")

                    owner = tags.get("owner", None)
                    bu = tags.get("bu", None)
                    product = tags.get("product", None)

                    issue_summary = (f"Redshift unencrypted cluster '{cluster_id}'"
                                     f"in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    issue_description = (
                        f"The Redshift Cluster is unencrypted.\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*Region*: {region}\n"
                        f"*Redshift Cluster ID*: {cluster_id}\n")

                    issue_description += JiraOperations.build_tags_table(tags)

                    if self.config.redshiftEncrypt.remediation:
                        auto_remediation_date = (self.config.now + self.config.redshiftEncrypt.issue_retention_date).date()
                        issue_description += f"\n{{color:red}}*Auto-Remediation Date*: {auto_remediation_date}{{color}}\n\n"

                    issue_description += "\n"
                    issue_description += (
                        f"*Recommendation*: \n"
                        f"Modify an unencrypted cluster.\n\n"
                    )

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["redshift-unencrypted-clusters"],
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
        obj = CreateRedshiftUnencryptedInstanceTickets(config)
        obj.create_tickets_redshift_unencrypted_cluster()
    except Exception:
        logging.exception("Failed to create redshift unencrypted cluster tickets")
