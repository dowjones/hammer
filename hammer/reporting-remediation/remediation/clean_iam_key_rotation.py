"""
Class for IAM User access key rotation.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import IssueStatus, IAMKeyRotationIssue
from library.aws.iam import IAMOperations
from library.aws.utility import Account
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanIAMUserStaleKeys:
    """ Class for IAM User access key rotation """
    def __init__(self, config):
        self.config = config

    def clean_iam_access_keys(self, batch=False):
        """ Class method to remediate IAM User access key """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.iamUserKeysRotation.ddb_table_name)

        retention_period = self.config.iamUserKeysRotation.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.iamUserKeysRotation.remediation_accounts.items():
            logging.debug("* Account Name:" + account_name + " :::Account ID:::" + account_id)
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, IAMKeyRotationIssue)
            for issue in issues:
                key_id = issue.issue_id
                username = issue.issue_details.username

                user_in_whitelist = self.config.iamUserKeysRotation.in_whitelist(account_id, username)
                key_in_whitelist = self.config.iamUserKeysRotation.in_whitelist(account_id, key_id)

                if user_in_whitelist or key_in_whitelist:
                    logging.debug(f"Skipping '{key_id} / {username}' (in whitelist)")

                    # Adding label with "whitelisted" to jira ticket.
                    jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        label=IssueStatus.Whitelisted.value
                    )
                    continue

                if issue.timestamps.reported is None:
                        logging.debug(f"Skipping '{key_id} / {username}' (was not reported)")
                        continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping '{key_id} / {username}' (has been already remediated)")
                    continue

                updated_date = issue.timestamp_as_datetime
                no_of_days_issue_created = (self.config.now - updated_date).days

                if no_of_days_issue_created >= retention_period:
                    try:
                        if not batch and \
                           not confirm(f"Do you want to remediate stale access key '{key_id} / {username}'", False):
                            continue

                        account = Account(id=account_id,
                                          name=account_name,
                                          role_name=self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        logging.debug(f"Remediating stale access key '{key_id} / {username}'")
                        remediation_succeed = True
                        try:
                            IAMOperations.disable_access_key(account.client("iam"), username, key_id)
                            comment = (f"Stale access key '{key_id} / {username}' issue "
                                       f"in '{account_name} / {account_id}' account "
                                       f"was remediated by hammer")
                        except Exception:
                            remediation_succeed = False
                            logging.exception("Failed to disable '{key_id} / {username}' stale access key")
                            comment = (f"Failed to remediate stale access key '{key_id} / {username}' issue "
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
                            account_id=account_id,
                        )
                        IssueOperations.set_status_remediated(ddb_table, issue)
                    except Exception:
                        logging.exception(f"Error occurred while disabling '{key_id} / {username}' "
                                          f"in '{account_name} / {account_id}'")
                else:
                    logging.debug(f"Skipping '{key_id} / {username}' "
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

    parser = argparse.ArgumentParser()
    parser.add_argument('--batch', action='store_true', help='Do not ask confirmation for remediation')
    args = parser.parse_args()

    try:
        class_object = CleanIAMUserStaleKeys(config)
        class_object.clean_iam_access_keys(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean stale IAM user keys")
