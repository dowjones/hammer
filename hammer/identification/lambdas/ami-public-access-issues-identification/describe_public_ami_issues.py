import json
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.ec2 import PublicAMIChecker
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, PublicAMIIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to evaluate public ami issues"""
    set_logging(level=logging.INFO)

    try:
        payload = json.loads(event["Records"][0]["Sns"]["Message"])
        account_id = payload['account_id']
        account_name = payload['account_name']
        # get the last region from the list to process
        region = payload['regions'].pop()
    except Exception:
        logging.exception(f"Failed to parse event\n{event}")
        return

    try:
        config = Config()

        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(config.publicAMIs.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          region=region,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for Public AMI issues for {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, PublicAMIChecker)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"Public AMIs in DDB:\n{open_issues.keys()}")

        checker = PublicAMIChecker(account=account)
        if not checker.check():
            return

        for ami in checker.amis:
            logging.debug(f"Checking {ami.id}")
            if ami.public_access:
                issue = PublicAMIIssue(account_id, ami.id)
                issue.issue_details.tags = ami.tags
                issue.issue_details.name = ami.name
                issue.issue_details.region = region
                if config.publicAMIs.in_whitelist(account_id, ami.id) or config.publicAMIs.in_whitelist(account_id, ami.id):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {ami.id}/{ami.id} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from issues_list_from_db (if exists)
                # as we already checked it
                open_issues.pop(ami.id, None)

        logging.debug(f"Public AMIs in DDB:\n{open_issues.keys()}")
        # all other unresolved issues in DDB are for removed/remediated keys
        for issue in open_issues.values():
            IssueOperations.set_status_resolved(ddb_table, issue)
    except Exception:
        logging.exception(f"Failed to check AMI public access for '{account_id} ({account_name})'")
        return

    # push SNS messages until the list with regions to check is empty
    if len(payload['regions']) > 0:
        try:
            Sns.publish(payload["sns_arn"], payload)
        except Exception:
            logging.exception("Failed to chain insecure services checking")

    logging.debug(f"Checked AMI public access for '{account_id} ({account_name})'")