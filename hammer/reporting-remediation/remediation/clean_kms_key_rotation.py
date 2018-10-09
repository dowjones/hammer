"""
Class for KMS key rotation remediation.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.aws.kms import KMSKeyChecker
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import KmsKeyRotationIssue
from library.aws.utility import Account
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanKMSKeyRotation(object):
    """ Class for  KMS key rotation remediation """
    def __init__(self, config):
        self.config = config

    def clean_kms_key_rotation(self, batch=False):
        """ Class method to remediate KMS key rotation """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.kmsKeysRotation.ddb_table_name)

        retention_period = self.config.kmsKeysRotation.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.kmsKeysRotation.remediation_accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, KmsKeyRotationIssue)
            for issue in issues:
                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping '{issue.issue_id}' (has been already remediated)")
                    continue

                in_whitelist = self.config.kmsKeysRotation.in_whitelist(account_id, issue.issue_id)
                if in_whitelist:
                    logging.debug(f"Skipping '{issue.issue_id}' (in whitelist)")
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
                           not confirm(f"Do you want to remediate kms key rotation enabled '{issue.issue_id}'", False):
                            continue

                        account = Account(id=account_id,
                                          name=account_name,
                                          region=issue.issue_details.region,
                                          role_name=self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        checker = KMSKeyChecker(account=account)
                        checker.check(ids=[issue.issue_id])
                        kms_key = checker.get_key(issue.issue_id)
                        remediation_succeed = True
                        try:
                            kms_key.enable()
                            comment = (f"KMS '{issue.issue_id}' issue "
                                       f"in '{account_name} / {account_id}' account, '{issue.issue_details.region}' region "
                                       f"was remediated by hammer")
                        except Exception:
                            remediation_succeed = False
                            logging.exception(f"Failed to enable '{issue.issue_id}' kms key rotation")
                            comment = (f"Failed to remediate KMS key rotation '{issue.issue_id}' issue "
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
                        logging.exception(f"Error occurred while updating KMS keys {issue.issue_id} "
                                          f"in {account_id}/{issue.issue_details.region}")


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

    parser = argparse.ArgumentParser()
    parser.add_argument('--batch', action='store_true', help='Do not ask confirmation for remediation')
    args = parser.parse_args()

    try:
        obj = CleanKMSKeyRotation(config)
        obj.clean_kms_key_rotation(batch=args.batch)
    except Exception:
        logging.exception("Failed to enable kms key rotation")
