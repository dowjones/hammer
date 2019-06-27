"""
Class to create Elasticsearch domain logging issue tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.aws.utility import Account
from library.config import Config
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, ESLoggingIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateElasticSearchDomainLoggingIssueTickets(object):
    """ Class to create elasticsearch domain logging issue tickets """
    def __init__(self, config):
        self.config = config

    def create_tickets_elasticsearch_domain_logging(self):
        """ Class method to create jira tickets """
        table_name = self.config.esLogging.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.esLogging.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, ESLoggingIssue)
            for issue in issues:
                domain_name = issue.issue_id
                region = issue.issue_details.region
                tags = issue.issue_details.tags

                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} Elasticsearch domain logging "
                                      f"'{domain_name}' issue")

                        comment = (f"Closing {issue.status.value} Elasticsearch domain logging '{domain_name}' issue "
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
                    # issue.status != IssueStatus.Closed (should be IssueStatus.Open)
                    elif issue.timestamps.updated > issue.timestamps.reported:
                        logging.error(f"TODO: update jira ticket with new data: {table_name}, {account_id}, {domain_name}")
                        slack.report_issue(
                            msg=f"Elasticsearch domain logging '{domain_name}' issue is changed "
                                f"in '{account_name} / {account_id}' account, '{region}' region"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_updated(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{domain_name}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting Elasticsearch domain logging '{domain_name}' issue")

                    owner = tags.get("owner", None)
                    bu = tags.get("bu", None)
                    product = tags.get("product", None)

                    issue_description = (
                        f"Elasticsearch domain logging is not enabled.\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*Region*: {region}\n"
                        f"*Domain ID*: {domain_name}\n"
                    )

                    issue_description += JiraOperations.build_tags_table(tags)

                    if self.config.esLogging.remediation:
                        auto_remediation_date = (self.config.now + self.config.esLogging.issue_retention_date).date()
                        issue_description += f"\n{{color:red}}*Auto-Remediation Date*: {auto_remediation_date}{{color}}\n\n"

                    issue_description += (
                        f"*Recommendation*: "
                        f"Enable logging for Elasticesearch domain. "
                        f"Elasticsearch logs contain information about errors and warnings raised "
                        f"during the operation of the service and can be useful for troubleshooting.. "
                    )

                    issue_summary = (f"Elasticsearch domain logging issue '{domain_name}' "
                                     f" in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["es-domain-logging"],
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
        obj = CreateElasticSearchDomainLoggingIssueTickets(config)
        obj.create_tickets_elasticsearch_domain_logging()
    except Exception:
        logging.exception("Failed to create Elasticsearch domain logging issue tickets")
