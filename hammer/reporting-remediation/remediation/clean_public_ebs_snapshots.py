"""
Class for public ebs snapshot remediation.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import IssueStatus, EBSPublicSnapshotIssue
from library.aws.ebs import EBSPublicSnapshotsChecker
from library.aws.utility import Account
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanPublicEBSSnapshots(object):
    """ Class for public ebs snapshot remediation """
    def __init__(self, config):
        self.config = config

    def clean_public_ebs_snapshots(self, batch=False):
        """ Class method to remediate public EBS snapshot """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.ebsSnapshot.ddb_table_name)

        retention_period = self.config.ebsSnapshot.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.ebsSnapshot.remediation_accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, EBSPublicSnapshotIssue)
            for issue in issues:
                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping '{issue.issue_id}' (has been already remediated)")
                    continue

                in_whitelist = self.config.ebsSnapshot.in_whitelist(account_id, issue.issue_id)
                if in_whitelist:
                    logging.debug(f"Skipping '{issue.issue_id}' (in whitelist)")

                    # Adding label with "whitelisted" to jira ticket.
                    jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        label=IssueStatus.Whitelisted.value
                    )
                    continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{issue.issue_id}' (was not reported)")
                    continue

                updated_date = issue.timestamp_as_datetime
                no_of_days_issue_created = (self.config.now - updated_date).days

                if no_of_days_issue_created >= retention_period:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    try:
                        if not batch and \
                           not confirm(f"Do you want to remediate public EBS snapshot '{issue.issue_id}'", False):
                            continue

                        account = Account(id=account_id,
                                          name=account_name,
                                          region=issue.issue_details.region,
                                          role_name=self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        checker = EBSPublicSnapshotsChecker(account=account)
                        checker.check(ids=[issue.issue_id])
                        snapshot = checker.get_snapshot(issue.issue_id)
                        remediation_succeed = True
                        try:
                            snapshot.make_private()
                            comment = (f"EBS public snapshot '{issue.issue_id}' issue "
                                       f"in '{account_name} / {account_id}' account, '{issue.issue_details.region}' region "
                                       f"was remediated by hammer")
                        except Exception:
                            remediation_succeed = False
                            logging.exception(f"Failed to make private '{issue.issue_id}' EBS public snapshot")
                            comment = (f"Failed to remediate EBS public snapshot '{issue.issue_id}' issue "
                                       f"in '{account_name} / {account_id}' account, '{issue.issue_details.region}' region "
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
                        logging.exception(f"Error occurred while updating EBS snapshot '{issue.issue_id}' "
                                          f"in {account_id}")
                else:
                    logging.debug(f"Skipping '{issue.issue_id}' "
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
        class_object = CleanPublicEBSSnapshots(config)
        class_object.clean_public_ebs_snapshots(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean EBS snapshots")
