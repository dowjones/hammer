"""
Class to remediate AMI public access.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import PublicAMIIssue, IssueStatus
from library.aws.ec2 import PublicAMIChecker
from library.aws.utility import Account
from library.utility import SingletonInstance, SingletonInstanceException


class CleanAMIPublicAccess:
    """ Class to remediate AMI public access """
    def __init__(self, config):
        self.config = config

    def clean_ami_public_access(self):
        """ Class method to clean AMI public access which are violating aws best practices """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.publicAMIs.ddb_table_name)

        retention_period = self.config.publicAMIs.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, PublicAMIIssue)
            for issue in issues:
                ami_id = issue.issue_id

                in_whitelist = self.config.publicAMIs.in_whitelist(account_id, ami_id)

                if in_whitelist:
                    logging.debug(f"Skipping {ami_id} (in whitelist)")

                    # Adding label with "whitelisted" to jira ticket.
                    jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        label=IssueStatus.Whitelisted.value
                    )
                    continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{ami_id}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping {ami_id} (has been already remediated)")
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

                        checker = PublicAMIChecker(account=account)
                        checker.check(amis_to_check=[ami_id])
                        ami = checker.get_ami(ami_id)
                        if ami is None:
                            logging.debug(f"AMI {ami_id} was removed by user")
                        elif not ami.public_access:
                            logging.debug(f"AMI {ami.name} public access issue was remediated by user")
                        else:
                            logging.debug(f"Remediating '{ami.name}' ")

                            remediation_succeed = True
                            if ami.modify_image_attribute():
                                comment = (f"AMI '{ami.name}' public access issue "
                                           f"in '{account_name} / {account_id}' account "
                                           f"was remediated by hammer")
                            else:
                                remediation_succeed = False
                                comment = (f"Failed to remediate AMI '{ami.name}' public access issue "
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
                                owner=owner,
                                account_id=account_id,
                                bu=bu, product=product,
                            )
                            IssueOperations.set_status_remediated(ddb_table, issue)
                    except Exception:
                        logging.exception(f"Error occurred while updating AMI '{ami_id}' access "
                                          f"in '{account_name} / {account_id}'")
                else:
                    logging.debug(f"Skipping '{ami_id}' "
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
        class_object = CleanAMIPublicAccess(config)
        class_object.clean_ami_public_access()
    except Exception:
        logging.exception("Failed to clean AMI public access")
