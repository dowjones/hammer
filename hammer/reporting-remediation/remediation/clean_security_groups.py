"""
Class to clean bad security groups
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.aws.security_groups import SecurityGroupsChecker, RestrictionStatus
from library.aws.utility import Account
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import IssueStatus, SecurityGroupIssue
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanSecurityGroups(object):
    """ Class to clean unrestricted security groups """
    def __init__(self, config):
        self.config = config

    def clean_security_groups(self, batch=False):
        """ Class function to clean security groups which are violating aws best practices """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.sg.ddb_table_name)
        backup_bucket = config.aws.s3_backup_bucket

        retention_period = self.config.sg.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.sg.remediation_accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, SecurityGroupIssue)
            for issue in issues:
                group_name = issue.issue_details.name
                group_vpc_id = issue.issue_details.vpc_id
                group_id = issue.issue_id
                group_region = issue.issue_details.region
                # status = issue.jira_details.status

                name_in_whitelist = self.config.sg.in_whitelist(account_id, f"{group_vpc_id}:{group_name}")
                id_in_whitelist = self.config.sg.in_whitelist(account_id, group_id)

                if name_in_whitelist or id_in_whitelist:
                    logging.debug(f"Skipping '{group_name} / {group_id}' (in whitelist)")

                    # Adding label with "whitelisted" to jira ticket.
                    jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        label=IssueStatus.Whitelisted.value
                    )
                    continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{group_name} / {group_id}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping '{group_name} / {group_id}' (has been already remediated)")
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
                                          region=group_region,
                                          role_name = self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        checker = SecurityGroupsChecker(account=account,
                                                        restricted_ports=self.config.sg.restricted_ports)
                        checker.check(ids=[group_id])
                        sg = checker.get_security_group(group_id)
                        if sg is None:
                            logging.debug(f"Security group '{group_name} / {group_id}' was removed by user")
                        elif sg.restricted:
                            logging.debug(f"Security group '{group_name} / {group_id}' issue was remediated by user")
                        elif sg.status != RestrictionStatus.OpenCompletely:
                            logging.debug(f"Security group '{group_name} / {group_id}' is not completely open")
                        else:
                            if not batch and \
                               not confirm(f"Do you want to remediate security group '{group_name} / {group_id}'", False):
                                continue

                            logging.debug(f"Remediating '{group_name} / {group_id}' rules")

                            backup_path = sg.backup_s3(main_account.client("s3"), backup_bucket)
                            remediation_succeed = True
                            processed = sg.restrict(RestrictionStatus.OpenCompletely)
                            if processed == 0:
                                logging.debug(f"No rules were detected to remediate in '{group_name} / {group_id}'")
                                comment = None
                            elif processed is None:
                                remediation_succeed = False
                                comment = (f"Failed to remediate security group '{group_name} / {group_id}' issue "
                                           f"in '{account_name} / {account_id}' account, '{group_region}' region "
                                           f"due to some limitations. Please, check manually")
                            else:
                                comment = (f"Rules backup was saved to "
                                           f"[{backup_path}|https://s3.console.aws.amazon.com/s3/object/{backup_bucket}/{backup_path}]. "
                                           f"Security group '{group_name} / {group_id}' `{RestrictionStatus.OpenCompletely.value}` issue "
                                           f"in '{account_name} / {account_id}' account, '{group_region}' region "
                                           f"was remediated by hammer")

                            if comment is not None:
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
                        logging.exception(f"Error occurred while updating security group '{group_name} / {group_id}' rules "
                                          f"in '{account_name} / {account_id} / {group_region}'")
                else:
                    logging.debug(f"Skipping '{group_name} / {group_id}' "
                                  f"({retention_period - no_of_days_issue_created} days before remediation)")


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

    parser = argparse.ArgumentParser()
    parser.add_argument('--batch', action='store_true', help='Do not ask confirmation for remediation')
    args = parser.parse_args()

    try:
        obj = CleanSecurityGroups(config)
        obj.clean_security_groups(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean security groups")
