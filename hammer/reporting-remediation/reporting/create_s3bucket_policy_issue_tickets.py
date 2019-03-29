"""
Class to create s3 bucket tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.aws.utility import Account
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, S3PolicyIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateS3BucketPolicyIssueTickets:
    """ Class to create s3 bucket tickets """
    def __init__(self, config):
        self.config = config

    def attachment_name(self, account_id, bucket_name):
        return f"{account_id}_{bucket_name}_{self.config.now.isoformat('T', 'seconds')}.json"

    def create_tickets_s3buckets(self):
        """ Class method to create jira tickets """
        table_name = self.config.s3policy.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.s3policy.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, S3PolicyIssue)
            for issue in issues:
                bucket_name = issue.issue_id
                tags = issue.issue_details.tags
                policy = issue.issue_details.policy
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.issue_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} S3 bucket '{bucket_name}' public policy issue")

                        comment = (f"Closing {issue.status.value} S3 bucket '{bucket_name}' public policy "
                                   f"in '{account_name} / {account_id}' account ")
                        if issue.status == IssueStatus.Whitelisted:
                            # Adding label with "whitelisted" to jira ticket.
                            jira.add_label(
                                ticket_id=issue.jira_details.ticket,
                                label=IssueStatus.Whitelisted.value
                            )
                        jira.close_issue(
                            ticket_id=issue.jira_details.ticket,
                            comment=comment
                        )
                        slack.report_issue(
                            msg=f"{comment}"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_closed(ddb_table, issue)
                    # issue.status != IssueStatus.Closed (should be IssueStatus.Open)
                    elif issue.timestamps.updated > issue.timestamps.reported:
                        logging.debug(f"Updating S3 bucket '{bucket_name}' public policy issue")

                        comment = "Issue details are changed, please check again.\n"
                        # Adding new bucket policy json as attachment to Jira ticket.
                        attachment = jira.add_attachment(
                            ticket_id=issue.jira_details.ticket,
                            filename=self.attachment_name(account_id, bucket_name),
                            text=policy
                        )
                        if attachment is not None:
                            comment += f"New policy - [^{attachment.filename}].\n"
                        comment += JiraOperations.build_tags_table(tags)
                        jira.update_issue(
                            ticket_id=issue.jira_details.ticket,
                            comment=comment
                        )
                        slack.report_issue(
                            msg=f"S3 bucket '{bucket_name}' pubic policy issue is changed "
                                f"in '{account_name} / {account_id}' account"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_updated(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{bucket_name}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting S3 bucket '{bucket_name}' public policy issue")

                    owner = tags.get("owner", None)
                    bu = tags.get("bu", None)
                    product = tags.get("product", None)

                    if bu is None:
                        bu = self.config.get_bu_by_name(bucket_name)

                    issue_summary = (f"S3 bucket '{bucket_name}' with public policy "
                                     f"in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    issue_description = (
                        f"Bucket policy allows unrestricted public access.\n\n"
                        f"*Threat*: "
                        f"This creates potential security vulnerabilities by allowing anyone to add, modify, or remove items in a bucket.\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*S3 Bucket name*: {bucket_name}\n"
                        f"*Bucket Owner*: {owner}\n"
                        f"\n")

                    auto_remediation_date = (self.config.now + self.config.s3policy.issue_retention_date).date()
                    issue_description += f"\n{{color:red}}*Auto-Remediation Date*: {auto_remediation_date}{{color}}\n\n"

                    issue_description += JiraOperations.build_tags_table(tags)

                    issue_description += f"\n"
                    issue_description += (
                        f"*Recommendation*: "
                        f"Grant CloudFront OAI applicable permissions on bucket "
                        f"or update bucket permissions with VPC CIDRs ranges or ip addresses/ranges from "
                        f"[RFC1918|https://tools.ietf.org/html/rfc1918]. "
                    )

                    if self.config.whitelisting_procedure_url:
                        issue_description += (f"For any other exceptions, please follow the [whitelisting procedure|{self.config.whitelisting_procedure_url}] "
                                              f"and provide a strong business reasoning. ")

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["publics3"],
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                    except Exception:
                        logging.exception("Failed to create jira ticket")
                        continue

                    if response is not None:
                        issue.jira_details.ticket = response.ticket_id
                        issue.jira_details.ticket_assignee_id = response.ticket_assignee_id
                        # Adding bucket policy json as attachment to Jira ticket.
                        jira.add_attachment(ticket_id=issue.jira_details.ticket,
                                            filename=self.attachment_name(account_id, bucket_name),
                                            text=policy)

                    issue.jira_details.owner = owner
                    issue.jira_details.business_unit = bu
                    issue.jira_details.product = product

                    slack.report_issue(
                        msg=f"Discovered {issue_summary}"
                            f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                        owner=owner,
                        account_id=account_id,
                        bu=bu, product=product,
                    )

                    IssueOperations.set_status_reported(ddb_table, issue)


if __name__ == '__main__':
    module_name = sys.modules[__name__].__loader__.name
    set_logging(level=logging.DEBUG, logfile=f"/var/log/hammer/{module_name}.log")
    config = Config()
    add_cw_logging(config.local.log_group,
                   log_stream=module_name,
                   level=logging.DEBUG,
                   region=config.aws.region)
    try:
        si = SingletonInstance(module_name)
    except SingletonInstanceException:
        logging.error(f"Another instance of '{module_name}' is already running, quitting")
        sys.exit(1)

    try:
        obj = CreateS3BucketPolicyIssueTickets(config)
        obj.create_tickets_s3buckets()
    except Exception:
        logging.exception("Failed to create S3 policy tickets")
