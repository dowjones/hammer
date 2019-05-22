import json
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.s3 import S3EncryptionChecker
from library.aws.utility import Account, DDB
from library.ddb_issues import IssueStatus, S3EncryptionIssue
from library.ddb_issues import Operations as IssueOperations


def lambda_handler(event, context):
    """ Lambda handler to evaluate s3 buckets encryption """
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
        ddb_table = main_account.resource("dynamodb").Table(config.s3Encrypt.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for S3 encryption in {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, S3EncryptionIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"S3 in DDB:\n{open_issues.keys()}")

        checker = S3EncryptionChecker(account=account)
        if not checker.check():
            return

        for bucket in checker.buckets:
            logging.debug(f"Checking {bucket.name}")
            if not bucket.encrypted:
                issue = S3EncryptionIssue(account_id, bucket.name)
                issue.issue_details.owner = bucket.owner
                issue.issue_details.tags = bucket.tags
                if config.s3Encrypt.in_whitelist(account_id, bucket.name):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {bucket.name} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from issues_list_from_db (if exists)
                # as we already checked it
                open_issues.pop(bucket.name, None)

        logging.debug(f"S3 in DDB:\n{open_issues.keys()}")
        # all other unresolved issues in DDB are for removed/remediated buckets
        for issue in open_issues.values():
            IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check S3 encryption for '{account_id} ({account_name})'")
        return

    logging.debug(f"Checked S3 encryption for '{account_id} ({account_name})'")