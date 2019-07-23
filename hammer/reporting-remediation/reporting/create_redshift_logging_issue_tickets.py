"""
Class to create redshift cluster logging issue tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.aws.utility import Account
from library.config import Config
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, RedshiftLoggingIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateRedshiftLoggingIssueTickets(object):
    """ Class to create redshift cluster logging issue tickets """
    def __init__(self, config):
        self.config = config

    def create_tickets_redshift_logging(self):
        """ Class method to create jira tickets """
        table_name = self.config.redshift_logging.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, RedshiftLoggingIssue)
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
                        logging.debug(f"Closing {issue.status.value} Redshift logging '{cluster_id}' issue")

                        comment = (f"Closing {issue.status.value} Redshift cluster logging '{cluster_id}' issue "
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
                    logging.debug(f"Reporting Redshift cluster logging '{cluster_id}' issue")

                    owner = tags.get("owner", None)
                    bu = tags.get("bu", None)
                    product = tags.get("product", None)

                    issue_summary = (f"Redshift logging is not enabled for '{cluster_id}'"
                                     f"in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    issue_description = (
                        f"The Redshift Cluster audit logging is not enabled.\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*Region*: {region}\n"
                        f"*Redshift Cluster ID*: {cluster_id}\n")

                    issue_description += JiraOperations.build_tags_table(tags)

                    issue_description += "\n"
                    issue_description += (
                        f"*Recommendation*: "
                        f"Enable logging for Redshift cluster. To enable logging, follow below steps:\n\n"
                        f"1. Sign in to the AWS Management Console and open the Amazon Redshift console.\n"
                        f"2. In the navigation pane, click Clusters.\n" 
                        f"3. In the list, click the cluster for which you want to enable logging.\n"
                        f"4. In the cluster details page, click Database, and then click Configure Audit Logging.\n"
                        f"5. In the Configure Audit Logging dialog box, in the Enable Audit Logging box, click Yes.\n"
                        f"6. For S3 Bucket, do one of the following:\n"
                        f" (a)If you already have an S3 bucket that you want to use, "
                        f"select Use Existing and then select the bucket from the Bucket list.\n"
                        f" (b)If you need a new S3 bucket,select Create New, and in New Bucket Name box, type a name.\n"
                        f"7. Optionally, in the S3 Key Prefix box, type a prefix to add to the S3 bucket.\n"
                        f"8. Click Save \n\n"
                    )

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["redshift-logging"],
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
        obj = CreateRedshiftLoggingIssueTickets(config)
        obj.create_tickets_redshift_logging()
    except Exception:
        logging.exception("Failed to create redshift cluster logging tickets")
