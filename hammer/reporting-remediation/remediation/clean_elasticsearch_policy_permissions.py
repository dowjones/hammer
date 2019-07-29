"""
Class to remediate ElasticSearch policy permissions.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import IssueStatus, ESPublicAccessIssue
from library.aws.elasticsearch import ESDomainChecker
from library.aws.utility import Account
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanElasticSearchPolicyPermissions:
    """ Class to remediate ElasticSearch domain policy permissions """
    def __init__(self, config):
        self.config = config

    def clean_elasticsearch_domain_policy_permissions(self, batch=False):
        """ Class method to clean ElasticSearch domains which are violating aws best practices """
        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(self.config.esPublicAccess.ddb_table_name)
        backup_bucket = config.aws.s3_backup_bucket

        retention_period = self.config.esPublicAccess.remediation_retention_period

        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.esPublicAccess.remediation_accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, ESPublicAccessIssue)
            for issue in issues:
                domain_name = issue.issue_id

                in_whitelist = self.config.esPublicAccess.in_whitelist(account_id, domain_name)
                #in_fixlist = self.config.esPublicAccess.in_fixnow(account_id, domain_name)

                if in_whitelist:
                    logging.debug(f"Skipping {domain_name} (in whitelist)")

                    # Adding label with "whitelisted" to jira ticket.
                    jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        label=IssueStatus.Whitelisted.value
                    )
                    continue
                # if not in_fixlist:
                #     logging.debug(f"Skipping {domain_name} (not in fixlist)")
                #     continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{domain_name}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping {domain_name} (has been already remediated)")
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

                        checker = ESDomainChecker(account=account)
                        checker.check(ids=[domain_name])
                        domain_details = checker.get_domain(domain_name)
                        if domain_details is None:
                            logging.debug(f"Elasticsearch domain {domain_name} was removed by user")
                        elif not domain_details.public:
                            logging.debug(f"Elasticsearch domain {domain_name} policy issue was remediated by user")
                        else:
                            if not batch and \
                               not confirm(f"Do you want to remediate elasticsearch domain '{domain_name}' policy", False):
                                continue

                            logging.debug(f"Remediating '{domain_name}' policy")

                            backup_path = domain_details.backup_policy_s3(main_account.client("s3"), backup_bucket)
                            remediation_succeed = True
                            if domain_details.restrict_policy():
                                comment = (f"Policy backup was saved to "
                                           f"[{backup_path}|https://s3.console.aws.amazon.com/s3/object/{backup_bucket}/{backup_path}]. "
                                           f"Domain '{domain_name}' policy issue "
                                           f"in '{account_name} / {account_id}' account "
                                           f"was remediated by hammer")
                            else:
                                remediation_succeed = False
                                comment = (f"Failed to remediate elasticsearch domain '{domain_name}' policy issue "
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
                        logging.exception(f"Error occurred while updating domain '{domain_name}' policy "
                                          f"in '{account_name} / {account_id}'")
                else:
                    logging.debug(f"Skipping '{domain_name}' "
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
        class_object = CleanElasticSearchPolicyPermissions(config)
        class_object.clean_elasticsearch_domain_policy_permissions(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean Elasticsearch domain public policies")
