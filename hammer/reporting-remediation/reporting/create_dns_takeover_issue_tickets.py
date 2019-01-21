"""
Class to create DNS takeover issue tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.aws.utility import Account
from library.utility import list_converter
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.aws.dns import DNSOperations
from library.ddb_issues import IssueStatus, DNSTakeoverIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateDNSTakeoverIssueTickets:
    """ Class to create DNS takeover issue tickets """
    def __init__(self, config):
        self.config = config

    def build_hosted_zones_table(self, hosted_zones):
        hosed_zone_details = ""

        if len(hosted_zones):
            hosed_zone_details += f"List of Hosted zone details with CNAME record sets: \n"
            hosed_zone_details += (
                f"||Hosted Zone ID||Name"
                f"||Is Private|CNAME Recordsets||\n")

            for hosted_zone in hosted_zones:
                hosed_zone_details += (
                    f"|{hosted_zone.id}|{hosted_zone.name}|{hosted_zone.type}"
                    f"|{list_converter(hosted_zone.cname_record_set)}|\n"
                )

        return hosed_zone_details

    def create_tickets_dns_takeover(self):
        """ Class method to create jira tickets """
        table_name = self.config.dnsTakeover.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, DNSTakeoverIssue)
            for issue in issues:
                dns_name = issue.issue_id
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.issue_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} Domain name '{dns_name}'")

                        comment = (f"Closing {issue.status.value} Domain name '{dns_name}'  "
                                   f"in '{account_name} / {account_id}' account ")
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
                        logging.debug(f"Updating Domain name '{dns_name}'")

                        comment = "Issue details are changed, please check again.\n"
                        jira.update_issue(
                            ticket_id=issue.jira_details.ticket,
                            comment=comment
                        )
                        slack.report_issue(
                            msg=f"Domain name '{dns_name}' issue is changed "
                                f"in '{account_name} / {account_id}' account"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_updated(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{dns_name}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting domain name '{dns_name}' dns takeover issue")

                    bu = None

                    if bu is None:
                        bu = self.config.get_bu_by_name(dns_name)

                    issue_summary = (f"DNS name '{dns_name}' is going expiry "
                                     f"in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    issue_description = f"Domain Name is going to expiry.\n\n"

                    auto_remediation_date = (self.config.now + self.config.dnsTakeover.issue_retention_date).date()
                    issue_description += f"\n{{color:red}}*Auto-Remediation Date*: {auto_remediation_date}{{color}}\n\n"

                    issue_description += (f"*Risk*: High\n\n"
                                       f"*Account Name*: {account_name}\n"
                                       f"*Account ID*: {account_id}\n"
                                       f"*Domain name*: {dns_name}\n\n")

                    account = Account(id=account_id,
                                      name=account_name,
                                      region=self.config.aws.region,
                                      role_name=self.config.aws.role_name_reporting)

                    dns_client = account.client("route53") if account.session is not None else None
                    hosted_zone_details = None

                    if dns_client is not None:
                        hosted_zones = DNSOperations.get_dns_hosted_zone_details(dns_client, dns_name)

                        hosted_zone_details = self.build_hosted_zones_table(hosted_zones)

                    issue_description += f"{hosted_zone_details if hosted_zone_details else ''}"

                    issue_description += f"\n"
                    issue_description += (
                        f"*Recommendation*: "
                        f"Renew the Domain and update Autorenew option as true.")

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["dns-takeover"],
                            account_id=account_id
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
        obj = CreateDNSTakeoverIssueTickets(config)
        obj.create_tickets_dns_takeover()
    except Exception:
        logging.exception("Failed to create DNS takeover tickets")
