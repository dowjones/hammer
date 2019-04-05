import json
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.iam import IAMKeyChecker
from library.aws.utility import Account, DDB
from library.ddb_issues import IssueStatus, IAMKeyRotationIssue
from library.ddb_issues import Operations as IssueOperations


def lambda_handler(event, context):
    """ Lambda handler to evaluate iam user keys rotation """
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
        ddb_table = main_account.resource("dynamodb").Table(config.iamUserKeysRotation.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for IAM user keys rotation for {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, IAMKeyRotationIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"Users with keys to rotate in DDB:\n{open_issues.keys()}")

        checker = IAMKeyChecker(account=account,
                                now=config.now,
                                rotation_criteria_days=config.iamUserKeysRotation.rotation_criteria_days)
        if not checker.check(last_used_check_enabled=False):
            return

        for user in checker.users:
            for key in user.stale_keys:
                issue = IAMKeyRotationIssue(account_id, key.id)
                issue.issue_details.username = user.id
                issue.issue_details.create_date = key.create_date.isoformat()
                if config.iamUserKeysRotation.in_whitelist(account_id, key.id) or config.iamUserKeysRotation.in_whitelist(account_id, user.id):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {key.id}/{user.id} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from issues_list_from_db (if exists)
                # as we already checked it
                open_issues.pop(key.id, None)

        logging.debug(f"Keys to rotate in DDB:\n{open_issues.keys()}")
        # all other unresolved issues in DDB are for removed/remediated keys
        for issue in open_issues.values():
            IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check IAM user keys rotation for '{account_id} ({account_name})'")
        return

    logging.debug(f"Checked IAM user keys rotation for '{account_id} ({account_name})'")
