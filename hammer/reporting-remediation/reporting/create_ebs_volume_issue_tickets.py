"""
Class to create ebs volume tickets.
"""
import sys
import logging


from collections import Counter
from library.logger import set_logging, add_cw_logging
from library.aws.utility import Account
from library.config import Config
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.aws.ec2 import EC2Operations
from library.ddb_issues import IssueStatus, EBSUnencryptedVolumeIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import empty_converter, list_converter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateEBSUnencryptedVolumeTickets(object):
    """ Class to create EBS volume tickets """
    def __init__(self, config):
        self.config = config

    def build_instances_table(self, instances):
        instance_details = ""
        owners = []
        bus = []
        products = []

        if len(instances) > 0:
            instance_details += f"*Instances*:\n"
            instance_details += (
                f"||Instance ID||State||Private Ip Address"
                f"||Public Ip Address"
                f"||Owner||Business unit||Product"
                f"||Volume State||\n")
            for props in instances:
                ec2_instance = props['ec2']
                state = props['state']
                owner = ec2_instance.tags.get('owner')
                bu = ec2_instance.tags.get('bu')
                product = ec2_instance.tags.get('product')

                instance_details += (
                    f"|{ec2_instance.id}|{ec2_instance.state}"
                    f"|{list_converter(ec2_instance.private_ips)}"
                    f"|{list_converter(ec2_instance.public_ips)}"
                    f"|{empty_converter(owner)}"
                    f"|{empty_converter(bu)}"
                    f"|{empty_converter(product)}"
                    f"|{empty_converter(state)}|\n")
                owners.append(owner)
                bus.append(bu)
                products.append(product)

        # remove empty and count number of occurrences for each owner/bu/product
        owners = Counter([x for x in owners if x])
        bus = Counter([x for x in bus if x])
        products = Counter([x for x in products if x])
        # find owner/bu/product with max occurrences
        owner = max(owners, key=lambda owner: owners[owner]) if owners else None
        bu = max(bus, key=lambda bu: bus[bu]) if bus else None
        product = max(products, key=lambda product: products[product]) if products else None
        # logging.debug(f"bu={bu}")
        # logging.debug(f"product={product}")

        return instance_details, owner, bu, product

    def create_tickets_ebsvolumes(self):
        """ Class method to create jira tickets """
        table_name = self.config.ebsVolume.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.ebsVolume.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, EBSUnencryptedVolumeIssue)
            for issue in issues:
                volume_id = issue.issue_id
                region = issue.issue_details.region
                tags = issue.issue_details.tags
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} EBS unencrypted volume '{volume_id}' issue")

                        comment = (f"Closing {issue.status.value} EBS unencrypted volume '{volume_id}' issue "
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
                        logging.error(f"TODO: update jira ticket with new data: {table_name}, {account_id}, {volume_id}")
                        slack.report_issue(
                            msg=f"EBS unencrypted volume '{volume_id}' issue is changed "
                                f"in '{account_name} / {account_id}' account, '{region}' region"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_updated(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{volume_id}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting EBS unencrypted volume '{volume_id}' issue")

                    # if owner/bu/product tags exist on volume - use it
                    volume_owner = tags.get("owner", None)
                    volume_bu = tags.get("bu", None)
                    volume_product = tags.get("product", None)

                    issue_description = (
                        f"EBS volume needs to be encrypted.\n\n"
                        f"*Risk*: High\n\n"
                        f"*Account Name*: {account_name}\n"
                        f"*Account ID*: {account_id}\n"
                        f"*Region*: {region}\n"
                        f"*Volume ID*: {volume_id}\n")

                    ec2_details = ec2_owner = ec2_bu = ec2_product = None
                    if issue.issue_details.attachments:
                        account = Account(id=account_id,
                                          name=account_name,
                                          region=region,
                                          role_name=self.config.aws.role_name_reporting)

                        if account.session is not None:
                            ec2_client = account.client("ec2")
                            ec2_instances = []
                            for instance_id, state in issue.issue_details.attachments.items():
                                metadata = EC2Operations.get_instance_meta_data(ec2_client, instance_id)
                                if metadata is not None:
                                    ec2_instances.append({
                                        'ec2': metadata,
                                        'state': state
                                    })
                            ec2_details, ec2_owner, ec2_bu, ec2_product = self.build_instances_table(ec2_instances)

                    owner = volume_owner if volume_owner is not None else ec2_owner
                    bu = volume_bu if volume_bu is not None else ec2_bu
                    product = volume_product if volume_product is not None else ec2_product

                    issue_description += JiraOperations.build_tags_table(tags)

                    issue_description += ec2_details if ec2_details else ''

                    issue_description += "*Recommendation*: Encrypt EBS volume. "

                    if self.config.whitelisting_procedure_url:
                        issue_description += (f"For any other exceptions, please follow the [whitelisting procedure|{self.config.whitelisting_procedure_url}] "
                                              f"and provide a strong business reasoning. ")

                    issue_summary = (f"EBS unencrypted volume '{volume_id}' "
                                     f" in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    # try:
                    #     response = jira.add_issue(
                    #         issue_summary=issue_summary, issue_description=issue_description,
                    #         priority="Major", labels=["unencrypted-ebs-volumes"],
                    #         owner=owner,
                    #         account_id=account_id,
                    #         bu=bu, product=product,
                    #     )
                    # except Exception:
                    #     logging.exception("Failed to create jira ticket")
                    #     continue
                    #
                    # if response is not None:
                    #     issue.jira_details.ticket = response.ticket_id
                    #     issue.jira_details.ticket_assignee_id = response.ticket_assignee_id

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
        obj = CreateEBSUnencryptedVolumeTickets(config)
        obj.create_tickets_ebsvolumes()
    except Exception:
        logging.exception("Failed to create EBS unencrypted volume tickets")
