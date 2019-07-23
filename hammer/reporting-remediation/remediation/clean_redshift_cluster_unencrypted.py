"""
Class to remediate Redshift cluster un-encryption issues.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import IssueStatus, RedshiftEncryptionIssue
from library.aws.redshift import RedshiftClusterChecker
from library.aws.utility import Account
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanRedshiftClusterUnencryption:
    """ Class to remediate Redshift cluster un-encryption issues """
    def __init__(self, config):
        self.config = config

    def cleanredshiftclusterunencryption(self, batch=False):
        """ Class method to clean Redshift cluster which are violating aws best practices """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.redshiftEncrypt.ddb_table_name)

        retention_period = self.config.redshiftEncrypt.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.aws.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, RedshiftEncryptionIssue)
            for issue in issues:
                cluster_id = issue.issue_id

                in_whitelist = self.config.redshiftEncrypt.in_whitelist(account_id, cluster_id)

                if in_whitelist:
                    logging.debug(f"Skipping {cluster_id} (in whitelist)")
                    # Adding label with "whitelisted" to jira ticket.
                    jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        labels=IssueStatus.Whitelisted.value
                    )
                    continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{cluster_id}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping {cluster_id} (has been already remediated)")
                    continue

                updated_date = issue.timestamp_as_datetime
                no_of_days_issue_created = (self.config.now - updated_date).days

                if no_of_days_issue_created >= retention_period:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    try:
                        if not batch and \
                           not confirm(f"Do you want to remediate '{cluster_id}' Redshift cluster un-encryption", False):
                            continue

                        account = Account(id=account_id,
                                          name=account_name,
                                          region=issue.issue_details.region,
                                          role_name=self.config.aws.role_name_reporting)
                        if account.session is None:
                            continue

                        checker = RedshiftClusterChecker(account=account)
                        checker.check(clusters=[cluster_id])
                        cluster_details = checker.get_cluster(cluster_id)

                        if cluster_id is None:
                            logging.debug(f"Redshift Cluster {cluster_details.name} was removed by user")
                        elif cluster_details.is_encrypt:
                            logging.debug(f"Cluster {cluster_details.name} Un-encryption issue was remediated by user")
                        else:
                            logging.debug(f"Remediating '{cluster_details.name}' Un-encryption")

                            remediation_succeed = True
                            if cluster_details.encrypt_cluster():
                                comment = (f"Cluster '{cluster_details.name}' un-encryption issue "
                                           f"in '{account_name} / {account_id}' account, '{issue.issue_details.region}'"
                                           f" region was remediated by hammer")
                            else:
                                remediation_succeed = False
                                comment = (f"Failed to remediate cluster '{cluster_details.name}' un-encryption issue "
                                           f"in '{account_name}/{account_id}' account, '{issue.issue_details.region}'"
                                           f" region due to some limitations. Please, check manually")

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
                        logging.exception(f"Error occurred while updating cluster '{cluster_id}' un-encryption "
                                          f"in '{account_name} / {account_id}'")
                else:
                    logging.debug(f"Skipping '{cluster_id}' "
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
        class_object = CleanRedshiftClusterUnencryption(config)
        class_object.cleanredshiftclusterunencryption(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean Redshift cluster unencryption")
