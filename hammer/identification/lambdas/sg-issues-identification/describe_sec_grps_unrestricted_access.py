import json
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.security_groups import SecurityGroupsChecker
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, SecurityGroupIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import DDB, Sns


def lambda_handler(event, context):
    """ Lambda handler to evaluate insecure services """
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
        ddb_table = main_account.resource("dynamodb").Table(config.sg.ddb_table_name)

        account = Account(id=account_id,
                          name=account_name,
                          region=region,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        logging.debug(f"Checking for insecure services in {account}")

        # existing open issues for account to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, SecurityGroupIssue)
        # make dictionary for fast search by id
        # and filter by current region
        open_issues = {issue.issue_id: issue for issue in open_issues if issue.issue_details.region == region}
        logging.debug(f"Security groups in DDB:\n{open_issues.keys()}")

        checker = SecurityGroupsChecker(account=account,
                                        restricted_ports=config.sg.restricted_ports)
        if checker.check():
            for sg in checker.groups:
                logging.debug(f"Checking {sg.name} ({sg.id})")
                if not sg.restricted:
                    # TODO: move instances detection for security group from reporting to identification
                    #ec2_instances = EC2Operations.get_instance_details_of_sg_associated(account.client("ec2"), sg.id)
                    #logging.debug(f"associated ec2 instances: {ec2_instances}")
                    issue = SecurityGroupIssue(account_id, sg.id)
                    issue.issue_details.name = sg.name
                    issue.issue_details.vpc_id = sg.vpc_id
                    issue.issue_details.region = sg.account.region
                    issue.issue_details.tags = sg.tags
                    issue.issue_details.status = sg.status.value
                    for perm in sg.permissions:
                        for ip_range in perm.ip_ranges:
                            if not ip_range.restricted:
                                issue.add_perm(perm.protocol, perm.from_port, perm.to_port, ip_range.cidr, ip_range.status)
                    if config.sg.in_whitelist(account_id, f"{sg.vpc_id}:{sg.name}") or \
                       config.sg.in_whitelist(account_id, sg.id):
                        issue.status = IssueStatus.Whitelisted
                    else:
                        issue.status = IssueStatus.Open
                    logging.debug(f"Setting {sg.id} status {issue.status}")
                    IssueOperations.update(ddb_table, issue)
                    # remove issue id from issues_list_from_db (if exists)
                    # as we already checked it
                    open_issues.pop(sg.id, None)

            logging.debug(f"Security groups in DDB:\n{open_issues.keys()}")
            # all other unresolved issues in DDB are for removed/remediated security groups
            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check insecure services in '{region}' for '{account_id} ({account_name})'")

    # push SNS messages until the list with regions to check is empty
    if len(payload['regions']) > 0:
        try:
            Sns.publish(payload["sns_arn"], payload)
        except Exception:
            logging.exception("Failed to chain insecure services checking")

    logging.debug(f"Checked insecure services in '{region}' for '{account_id} ({account_name})'")