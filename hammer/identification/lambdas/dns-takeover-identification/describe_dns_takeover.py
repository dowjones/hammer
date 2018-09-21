import json
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.dns import DNSTakeoverChecker
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, DNSTakeoverIssue
from library.ddb_issues import Operations as IssueOperations


def lambda_handler(event, context):
    """ Lambda handler to evaluate DNS takeover issue details."""
    set_logging(level=logging.DEBUG)

    try:
        payload = json.loads(event["Records"][0]["Sns"]["Message"])
        account_id = payload['account_id']
        account_name = payload['account_name']
    except Exception:
        logging.exception(f"Failed to parse event\n{event}")
        return

    try:
        config = Config()

        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(config.dnsTakeover.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for DNS takeover issue in {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, DNSTakeoverIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"DNS takeover issues in DDB:\n{open_issues.keys()}")

        checker = DNSTakeoverChecker(account=account,
                                     now=config.now,
                                     takeover_criteria=config.dnsTakeover.take_over_criteria_days)
        if not checker.check():
            return

        for domain in checker.domains:
            logging.debug(f"Checking {domain.name}")
            if domain.validate_expiry:
                issue = DNSTakeoverIssue(account_id, domain.name)
                if config.dnsTakeover.in_whitelist(account_id, domain.name):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {domain.name} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from issues_list_from_db (if exists)
                # as we already checked it
                open_issues.pop(domain.name, None)

        logging.debug(f"DNS takeover issues in DDB:\n{open_issues.keys()}")
        # all other unresolved issues in DDB are for removed/remediated domains
        for issue in open_issues.values():
            IssueOperations.set_status_resolved(ddb_table, issue)
    except Exception:
        logging.exception(f"Failed to check DNS takeover issue for '{account_id} ({account_name})'")
        return

    logging.debug(f"Checked DNS takeover issuefor '{account_id} ({account_name})'")