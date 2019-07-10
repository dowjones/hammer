import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.aws.utility import Account
from library.jiraoperations import JiraReporting
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus, CloudTrailIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import bool_converter, list_converter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateCloudTrailLoggingTickets:
    """ Class to handle cloud trail logging issues with reporting """
    def __init__(self, config):
        self.config = config

    def build_trail_status(self, disabled, errors):
        desc = "*Status*: " + ("Disabled" if disabled else "Enabled")
        if errors:
            desc += ", with logging errors"
        return desc

    def build_trails_table(self, trails):
        desc = f"*Trails*:"
        if trails:
            desc += f"\n"
            desc += f"||Trail ARN||Enabled||Multi Region||Selectors||Errors||\n"
            for trail in trails:
                errors = [f"{k}[{v['resource']}, {v['error']}]" for k, v in trail['errors'].items()]
                desc += (f"|{trail['id']}"
                         f"|{bool_converter(trail['enabled'])}"
                         f"|{bool_converter(trail['multi_region'])}"
                         f"|{trail['selectors']}"
                         f"|{list_converter(errors)}|\n")
        else:
            desc += f" not detected"
        return desc

    def create_tickets_cloud_trail_logging(self):
        """ Class function to create jira tickets """
        table_name = self.config.cloudtrails.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.cloudtrails.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, CloudTrailIssue)
            for issue in issues:
                region = issue.issue_id
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} '{region}' CloudTrail logging issue")

                        comment = (f"Closing {issue.status.value} issue with '{region}' CloudTrail logging in "
                                   f"'{account_name} / {account_id}'")
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
                            account_id=account_id,
                        )
                        IssueOperations.set_status_closed(ddb_table, issue)
                    # issue.status != IssueStatus.Closed (should be IssueStatus.Open)
                    elif issue.timestamps.updated > issue.timestamps.reported:
                        logging.debug(f"Updating '{region}' issue")

                        comment = "Issue details are changed, please check again.\n"
                        comment += self.build_trail_status(issue.issue_details.disabled, issue.issue_details.delivery_errors)
                        comment += f"\n\n"
                        comment += self.build_trails_table(issue.issue_details.trails)
                        jira.update_issue(
                            ticket_id=issue.jira_details.ticket,
                            comment=comment
                        )
                        slack.report_issue(
                            msg=f"CloudTrail logging '{region}' ssue is changed in "
                                f"'{account_name} / {account_id}'"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            account_id=account_id,
                        )
                        IssueOperations.set_status_updated(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{region}' issue")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting '{region}' CloudTrail logging issue")

                    if issue.issue_details.disabled:
                        issue_summary = f"Disabled CloudTrail in '{account_name} / {account_id} / {region}' "
                        issue_description = "No enabled CloudTrails for region available."
                        recommendation = f"Create CloudTrail for region"
                    elif issue.issue_details.delivery_errors:
                        issue_summary = f"CloudTrail logging issues in '{account_name} / {account_id} / {region}' "
                        issue_description = "CloudTrail has issues with logging."
                        recommendation = f"Check policies for CloudTrail logging"
                    else:
                        raise Exception("not disabled and no errors, this should not have happened")

                    issue_description = (
                        f"{issue_description}\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*Region*: {region}\n")

                    issue_description += self.build_trail_status(issue.issue_details.disabled, issue.issue_details.delivery_errors)

                    issue_description += self.build_trails_table(issue.issue_details.trails)

                    issue_description += f"\n\n*Recommendation*: {recommendation}. "

                    if self.config.whitelisting_procedure_url:
                        issue_description += (f"For any other exceptions, please follow the [whitelisting procedure|{self.config.whitelisting_procedure_url}] "
                                              f"and provide a strong business reasoning. ")

                    # try:
                    #     response = jira.add_issue(
                    #         issue_summary=issue_summary, issue_description=issue_description,
                    #         priority="Major", labels=["cloud-trail-disabled"],
                    #         account_id=account_id,
                    #     )
                    # except Exception:
                    #     logging.exception("Failed to create jira ticket")
                    #     continue
                    #
                    # if response is not None:
                    #     issue.jira_details.ticket = response.ticket_id
                    #     issue.jira_details.ticket_assignee_id = response.ticket_assignee_id

                    slack.report_issue(
                        msg=f"Discovered {issue_summary}"
                            f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                        account_id=account_id,
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
        obj = CreateCloudTrailLoggingTickets(config)
        obj.create_tickets_cloud_trail_logging()
    except Exception:
        logging.exception("Failed to create CloudTrail tickets")
