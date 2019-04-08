import json
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.cloudtrail import CloudTrailChecker
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, CloudTrailIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import DDB, Sns


def lambda_handler(event, context):
    """ Lambda Handler to describe cloud trails enabled or not for each region """
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
        ddb_table = main_account.resource("dynamodb").Table(config.cloudtrails.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          region=region,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for CloudTrail logging issues in {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, CloudTrailIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues if issue.issue_id == region}
        logging.debug(f"CloudTrail region in DDB:\n{open_issues.keys()}")

        checker = CloudTrailChecker(account=account)
        if checker.check():
            if checker.disabled or checker.delivery_errors:
                issue = CloudTrailIssue(account_id, region)
                issue.issue_details.disabled = checker.disabled
                issue.issue_details.delivery_errors = checker.delivery_errors
                issue.add_trails(checker.trails)
                if config.cloudtrails.in_whitelist(account_id, region):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {region} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
            # issue exists in ddb and was fixed
            elif region in open_issues:
                IssueOperations.set_status_resolved(ddb_table, open_issues[region])
        # track the progress of API request to scan specific account/region/feature
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check CloudTrail in '{region}' for '{account_id} ({account_name})'")

    # push SNS messages until the list with regions to check is empty
    if len(payload['regions']) > 0:
        try:
            Sns.publish(payload["sns_arn"], payload)
        except Exception:
            logging.exception("Failed to chain CloudTrail checking")

    logging.debug(f"Checked CloudTrail in '{region}' for '{account_id} ({account_name})'")
