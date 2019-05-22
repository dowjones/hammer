import json
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.iam import IAMKeyChecker
from library.aws.utility import Account, DDB
from library.ddb_issues import IssueStatus, IAMKeyInactiveIssue
from library.ddb_issues import Operations as IssueOperations


def lambda_handler(event, context):
    """ Lambda handler to evaluate iam user inactive keys """
    set_logging(level=logging.INFO)

    try:
        payload = json.loads(event["Records"][0]["Sns"]["Message"])
        account_id = payload['account_id']
        account_name = payload['account_name']
        # if request_id is present in payload then this lambda was called from the API
        request_id = payload.get('request_id', None)
    except Exception:
        logging.exception(f"Failed to parse event\n{event}")
        return

    try:
        config = Config()

        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(config.iamUserInactiveKeys.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for IAM user inactive keys in {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, IAMKeyInactiveIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"Users with inactive keys in DDB:\n{open_issues.keys()}")

        checker = IAMKeyChecker(account=account,
                                now=config.now,
                                inactive_criteria_days=config.iamUserInactiveKeys.inactive_criteria_days)
        if not checker.check(last_used_check_enabled=True):
            return

        for user in checker.users:
            for key in user.inactive_keys:
                issue = IAMKeyInactiveIssue(account_id, key.id)
                issue.issue_details.username = user.id
                issue.issue_details.last_used = key.last_used.isoformat()
                issue.issue_details.create_date = key.create_date.isoformat()
                if config.iamUserInactiveKeys.in_whitelist(account_id, key.id) or config.iamUserInactiveKeys.in_whitelist(account_id, user.id):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {key.id}/{user.id} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from open_issues (if exists)
                # as we already checked it
                open_issues.pop(key.id, None)

        logging.debug(f"Inactive keys in DDB:\n{open_issues.keys()}")
        # all other unresolved issues in DDB are for removed/remediated keys
        for issue in open_issues.values():
            IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check IAM user inactive keys for '{account_id} ({account_name})'")
        return

    logging.debug(f"Checked IAM user inactive keys for '{account_id} ({account_name})'")
