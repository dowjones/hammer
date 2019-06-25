"""
Class to create ecs privileged access issue tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.aws.utility import Account
from library.config import Config
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, ECSPrivilegedAccessIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateECSPrivilegedAccessIssueTickets(object):
    """ Class to create ECS privileged access issue tickets """
    def __init__(self, config):
        self.config = config

    def create_tickets_ecs_privileged(self):
        """ Class method to create jira tickets """
        table_name = self.config.ecs_privileged_access.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.ecs_privileged_access.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, ECSPrivilegedAccessIssue)
            for issue in issues:
                task_definition_name = issue.issue_id
                privileged_container_names = issue.issue_details.privileged_container_names
                region = issue.issue_details.region
                tags = issue.issue_details.tags
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} ECS privileged access disabled "
                                      f"'{task_definition_name}' issue")

                        comment = (f"Closing {issue.status.value} ECS privileged access disabled "
                                   f"'{task_definition_name}' issue "
                                   f"in '{account_name} / {account_id}' account, '{region}' region")
                        if issue.status == IssueStatus.Whitelisted:
                            # Adding label with "whitelisted" to jira ticket.
                            jira.add_label(
                                ticket_id=issue.jira_details.ticket,
                                labels=IssueStatus.Whitelisted
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
                            msg=f"ECS privileged access disabled '{task_definition_name}' issue is changed "
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
                    logging.debug(f"Reporting ECS privileged access issue for '{task_definition_name}'")

                    owner = tags.get("owner", None)
                    bu = tags.get("bu", None)
                    product = tags.get("product", None)

                    issue_summary = (f"ECS privileged access is enabled for '{task_definition_name}'"
                                     f"in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    issue_description = (
                        f"The ECS privileged access is enabled.\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*Region*: {region}\n"
                        f"*ECS Task Definition Name*: {task_definition_name}\n"
                        f"*ECS Task definition's privileged container names*: {privileged_container_names}\n"
                        f"*Container has privileged access*: True \n"
                    )

                    issue_description += JiraOperations.build_tags_table(tags)

                    issue_description += "\n"
                    issue_description += (
                        f"*Recommendation*: "
                        f"By default, containers are unprivileged and cannot. To disable ECS privileged access, "
                        f"follow below steps:"
                        f"1. Open the Amazon ECS console at https://console.aws.amazon.com/ecs/. \n"
                        f"2. From the navigation bar, "
                        f"choose region that contains your task definition and choose Task Definitions.\n"
                        f"3. On the Task Definitions page, select the box to the left of the task definition to revise "
                        f"and choose Create new revision.\n"
                        f"4. On the Create new revision of Task Definition page, "
                        f"select the container and disable 'Privileged' option  under section 'Security' "
                        f"and then choose Update.\n"
                        f"5. Verify the information and choose Create.\n"
                    )

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority="Major", labels=["ecs-privileged-access"],
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
        obj = CreateECSPrivilegedAccessIssueTickets(config)
        obj.create_tickets_ecs_privileged()
    except Exception:
        logging.exception("Failed to create ECS privileged access tickets")
