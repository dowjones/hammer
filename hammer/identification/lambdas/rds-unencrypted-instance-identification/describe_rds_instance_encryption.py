import json
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.rds import RdsEncryptionChecker
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, RdsEncryptionIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import DDB, Sns


def lambda_handler(event, context):
    """ Lambda handler to evaluate RDS data encrypted or not """
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
        ddb_table = main_account.resource("dynamodb").Table(config.rdsEncrypt.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          region=region,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for RDS encryption in {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, RdsEncryptionIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues if issue.issue_details.region == region}
        logging.debug(f"RDS encryption in DDB:\n{open_issues.keys()}")

        checker = RdsEncryptionChecker(account=account)
        if checker.check():
            for instance in checker.instances:
                logging.debug(f"Checking {instance.name} ({instance.id})")
                issue = RdsEncryptionIssue(account_id, instance.id)
                issue.issue_details.id = instance.id
                issue.issue_details.name = instance.name
                issue.issue_details.region = instance.account.region
                issue.issue_details.engine = instance.engine
                issue.issue_details.tags = instance.tags
                if config.rdsEncrypt.in_whitelist(account_id, instance.id):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {instance.id} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from issues_list_from_db (if exists)
                # as we already checked it
                open_issues.pop(instance.id, None)

            logging.debug(f"RDS encryption in DDB:\n{open_issues.keys()}")
            # all other unresolved issues in DDB are for removed/remediated RDS encryption
            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check RDS encryption in '{region}' for '{account_id} ({account_name})'")

    # push SNS messages until the list with regions to check is empty
    if len(payload['regions']) > 0:
        try:
            Sns.publish(payload["sns_arn"], payload)
        except Exception:
            logging.exception("Failed to chain RDS encryption checking")

    logging.debug(f"Checked RDS encrypted or not in '{region}' for '{account_id} ({account_name})'")