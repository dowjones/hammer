import json
import logging
import os

from library.logger import set_logging
from library.config import Config
from library.aws.ta import TrustedAdvisorChecker
from library.aws.utility import Account
from library.ddb_issues import IssueStatus
from library.ddb_issues import TACheckIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import Sns

def lambda_handler(event, context):
    """ Lambda handler to evaluate trusted advisor checks """
    set_logging(level=logging.DEBUG)

    try:
        payload = json.loads(event["Records"][0]["Sns"]["Message"])
        account_id = payload['account_id']
        checks = payload['checks']

    except Exception:
        logging.exception(f"Failed to parse event\n{event}")
        return

    try:
        config = Config()
        main_account = Account(region=config.aws.region)
        account = Account(id=account_id, role_name=config.aws.role_name_identification, region="us-east-1")

        for check in checks:
            check_id = check["id"]

            ddb_table_name = check["ddb.table_name"]
            filters = check["filters"]
            metadata = check["metadata"]
            ddb_table = main_account.resource("dynamodb").Table(ddb_table_name)
            category = check["category"]
            checkname = check["checkname"]

            open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, TACheckIssue)
            open_issues = {issue.issue_id: issue for issue in open_issues}
            logging.debug(f"TA in DDB:\n{open_issues.keys()}")

            checker = TrustedAdvisorChecker(account=account, check_id=check_id)

            #grab the trusted advisor response unfiltered
            result = checker.get_ta_result()
            filtered = False
            if filters:
                filtered = True
                result = checker.filter(filters, metadata, result)
            for vuln_resource in result["result"]["flaggedResources"]:
                resource_id = vuln_resource["resourceId"]
                issue = TACheckIssue(account_id,resource_id)
                issue.issue_details.status = vuln_resource["status"]
                issue.issue_details.filtered = filtered
                issue.issue_details.metadata = vuln_resource["metadata"]
                issue.issue_details.region = vuln_resource["region"]
                issue.issue_details.checkname = checkname
                issue.issue_details.category = category
                issue.status = IssueStatus.Open
                logging.debug("Setting status to Open")
                IssueOperations.update(ddb_table, issue)

                open_issues.pop(resource_id, None)

            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)


    except Exception:
        logging.exception(f"Failed to check Trusted Advisor findings for '{account_id}'")
        return
