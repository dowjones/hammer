import json
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.ecs import ECSChecker
from library.aws.utility import Account, DDB
from library.ddb_issues import IssueStatus, ECSLoggingIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to evaluate ECS logging enabled or not. """
    set_logging(level=logging.DEBUG)

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
        ddb_table = main_account.resource("dynamodb").Table(config.ecs_logging.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          region=region,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking logging enabled or not for ecs task definitions in {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, ECSLoggingIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues if issue.issue_details.region == region}
        logging.debug(f"ECS task definitions in DDB:\n{open_issues.keys()}")

        checker = ECSChecker(account=account)
        if checker.check():
            for task_definition in checker.task_definitions:
                logging.debug(f"Checking {task_definition.name}")
                if not task_definition.is_logging:
                    issue = ECSLoggingIssue(account_id, task_definition.name)
                    issue.issue_details.region = task_definition.account.region
                    issue.issue_details.task_definition_arn = task_definition.arn
                    issue.issue_details.disabled_logging_container_names = task_definition.disabled_logging_container_names
                    issue.issue_details.tags = task_definition.tags

                    if config.ecs_logging.in_whitelist(account_id, task_definition.name):
                        issue.status = IssueStatus.Whitelisted
                    else:
                        issue.status = IssueStatus.Open
                    logging.debug(f"Setting {task_definition.name} status {issue.status}")
                    IssueOperations.update(ddb_table, issue)
                    # remove issue id from issues_list_from_db (if exists)
                    # as we already checked it
                    open_issues.pop(task_definition.name, None)

            logging.debug(f"ECS task definitions in DDB:\n{open_issues.keys()}")
            # all other unresolved issues in DDB are for removed/remediated task definitions
            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)
        # track the progress of API request to scan specific account/region/feature
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check ECS task definitions for '{account_id} ({account_name})'")
        return

    # push SNS messages until the list with regions to check is empty
    if len(payload['regions']) > 0:
        try:
            Sns.publish(payload["sns_arn"], payload)
        except Exception:
            logging.exception("Failed to chain audit logging checking")

    logging.debug(f"Checked ECS task definitions for '{account_id} ({account_name})'")


