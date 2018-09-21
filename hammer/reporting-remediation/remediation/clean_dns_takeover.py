"""
Class to remediate Domain expiry details.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import DNSTakeoverIssue
from library.aws.dns import DNSTakeoverChecker
from library.aws.utility import Account


class CleanDNSTakeoverIssues:
    """ Class to remediate DNS takeover issues """
    def __init__(self, config):
        self.config = config

    def clean_dns_takeover(self):
        """ Class method to clean Route53 domains which are violating aws best practices """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.dnsTakeover.ddb_table_name)

        retention_period = self.config.dnsTakeover.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, DNSTakeoverIssue)
            for issue in issues:
                dns_name = issue.issue_id

                in_whitelist = self.config.dnsTakeover.in_whitelist(account_id, dns_name)
                #in_fixlist = self.config.dnsTakeover.in_fixnow(account_id, dns_name)

                if in_whitelist:
                    logging.debug(f"Skipping {dns_name} (in whitelist)")
                    continue
                # if not in_fixlist:
                #     logging.debug(f"Skipping {dns_name} (not in fixlist)")
                #     continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{dns_name}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping {dns_name} (has been already remediated)")
                    continue

                updated_date = issue.timestamp_as_datetime
                no_of_days_issue_created = (self.config.now - updated_date).days

                if no_of_days_issue_created >= retention_period:


                    try:
                        account = Account(id=account_id,
                                          name=account_name,
                                          region=issue.issue_details.region,
                                          role_name=self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        checker = DNSTakeoverChecker(account=account)
                        checker.check(domains=[dns_name])
                        domain = checker.get_domain(dns_name)
                        if domain is None:
                            logging.debug(f"Domain {dns_name} was removed by user")
                        elif not domain.validate_expiry:
                            logging.debug(f"Domain {domain.name} takeover issue was remediated by user")
                        else:
                            logging.debug(f"Remediating '{domain.name}' takeover issue")

                            remediation_succeed = True
                            if domain.renew_domain():
                                comment = (f"Domain '{domain.name}' takeover issue "
                                           f"in '{account_name} / {account_id}' account "
                                           f"was remediated by hammer")
                            else:
                                remediation_succeed = False
                                comment = (f"Failed to remediate domain '{domain.name}' takeover issue "
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
                                account_id=account_id
                            )
                            IssueOperations.set_status_remediated(ddb_table, issue)
                    except Exception:
                        logging.exception(f"Error occurred while updating domain '{dns_name}' "
                                          f"in '{account_name} / {account_id}'")
                else:
                    logging.debug(f"Skipping '{dns_name}' "
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
        class_object = CleanDNSTakeoverIssues(config)
        class_object.clean_dns_takeover()
    except Exception:
        logging.exception("Failed to clean DSN takeover issues")