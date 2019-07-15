"""
Class to create ecs external image source issue tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.aws.utility import Account
from library.config import Config
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, ECSExternalImageSourceIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateECSExternalImageSourceIssueTickets(object):
    """ Class to create ECS external image source issue tickets """
    def __init__(self, config):
        self.config = config

    def create_tickets_ecs_external_images(self):
        """ Class method to create jira tickets """
        table_name = self.config.ecs_external_image_source.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.ecs_external_image_source.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, ECSExternalImageSourceIssue)
            for issue in issues:
                task_definition_name = issue.issue_id
                region = issue.issue_details.region
                tags = issue.issue_details.tags
                container_image_details = issue.issue_details.container_image_details
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} ECS external image source '{task_definition_name}' issue")

                        comment = (f"Closing {issue.status.value} ECS external image source '{task_definition_name}' issue "
                                   f"in '{account_name} / {account_id}' account, '{region}' region")
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
                        logging.error(f"TODO: update jira ticket with new data: {table_name}, {account_id}, {task_definition_name}")
                        slack.report_issue(
                            msg=f"ECS external image source '{task_definition_name}' issue is changed "
                                f"in '{account_name} / {account_id}' account, '{region}' region"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_updated(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{task_definition_name}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting ECS external image source issue for '{task_definition_name}'")

                    owner = tags.get("owner", None)
                    bu = tags.get("bu", None)
                    product = tags.get("product", None)

                    issue_summary = (f"ECS external image source '{task_definition_name}'"
                                     f"in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    issue_description = (
                        f"The ECS image source taken from external source.\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*Region*: {region}\n"
                        f"*ECS Task Definition*: {task_definition_name}\n"
                        f"*ECS container image Source*: External \n"
                        f"*ECS container image details*: {container_image_details} \n"
                    )

                    issue_description += JiraOperations.build_tags_table(tags)

                    issue_description += "\n"
                    issue_description += (
                        f"*Recommendation*: "
                        f"For both security and reliability, use ECS container registry and maintain "
                        f"all required container images within ECS. "
                        f"To update ECS container image source follow below steps:\n"
                        f"1. Open the Amazon ECS console at https://console.aws.amazon.com/ecs/. \n"
                        f"2. From the navigation bar, choose region that contains your task definition "
                        f"and choose Task Definitions.\n"
                        f"3. On the Task Definitions page, select the box to left of task definition to revise "
                        f"and choose Create new revision.\n"
                        f"4. On the Create new revision of Task Definition page, select the container and "
                        f"add internal image source to 'Image' option and then choose Update.\n"
                        f"5. Verify the information and choose Create.\n"
                    )

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["ecs-external-image"],
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
        obj = CreateECSExternalImageSourceIssueTickets(config)
        obj.create_tickets_ecs_external_images()
    except Exception:
        logging.exception("Failed to create ECS external image issue tickets")
