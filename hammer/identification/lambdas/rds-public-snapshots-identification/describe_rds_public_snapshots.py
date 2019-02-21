import json
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.rds import RdsSnapshotsChecker
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, RdsPublicSnapshotIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import DDB, Sns


def lambda_handler(event, context):
    """ Lambda handler to evaluate public RDS snapshots """
    set_logging(level=logging.INFO)

    try:
        payload = json.loads(event["Records"][0]["Sns"]["Message"])
        account_id = payload['account_id']
        account_name = payload['account_name']
        # get the last region from the list to process
        region = payload['regions'].pop()
        # if request_id is present in payload then this lambda was called from the API
        request_id = payload.get('request_id', None)
    except Exception:
        logging.exception(f"Failed to parse event\n{event}")
        return

    try:
        config = Config()

        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(config.rdsSnapshot.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          region=region,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for public RDS snapshots in {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, RdsPublicSnapshotIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues if issue.issue_details.region == region}
        logging.debug(f"Public RDS snapshots in DDB:\n{open_issues.keys()}")

        checker = RdsSnapshotsChecker(account=account)
        if checker.check():
            for snapshot in checker.snapshots:
                logging.debug(f"Checking {snapshot.id} ({snapshot.db})")
                issue = RdsPublicSnapshotIssue(account_id, snapshot.id)
                issue.issue_details.db = snapshot.db
                issue.issue_details.name = snapshot.name
                issue.issue_details.region = snapshot.account.region
                issue.issue_details.engine = snapshot.engine
                issue.issue_details.tags = snapshot.tags
                if config.rdsSnapshot.in_whitelist(account_id, snapshot.id):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {snapshot.id} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from issues_list_from_db (if exists)
                # as we already checked it
                open_issues.pop(snapshot.id, None)

            logging.debug(f"RDS public snapshots in DDB:\n{open_issues.keys()}")
            # all other unresolved issues in DDB are for removed/remediated RDS snapshots
            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check public RDS snapshots in '{region}' for '{account_id} ({account_name})'")

    # push SNS messages until the list with regions to check is empty
    if len(payload['regions']) > 0:
        try:
            Sns.publish(payload["sns_arn"], payload)
        except Exception:
            logging.exception("Failed to chain public RDS snapshots checking")

    logging.debug(f"Checked public RDS snapshots in '{region}' for '{account_id} ({account_name})'")