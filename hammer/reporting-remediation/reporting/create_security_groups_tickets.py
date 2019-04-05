"""
Class to create jira tickets for security group issues.
"""
import sys
import logging
import warnings


from functools import lru_cache
from ipwhois import IPWhois
from collections import Counter
from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.aws.ec2 import EC2Operations
from library.aws.iam import IAMOperations
from library.ddb_issues import IssueStatus, SecurityGroupIssue
from library.ddb_issues import Operations as IssueOperations
from library.utility import empty_converter, list_converter, bool_converter
from library.aws.utility import Account
from library.aws.security_groups import RestrictionStatus
from library.aws.rds import RDSOperations
from library.utility import SingletonInstance, SingletonInstanceException


class CreateSecurityGroupsTickets(object):
    """ Class to create jira tickets for security group issues """
    def __init__(self, config):
        self.config = config

    @staticmethod
    @lru_cache(maxsize=128)
    def get_registrant(cidr):
        ip = cidr.split("/")[0]

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                whois = IPWhois(ip).lookup_rdap()
            except Exception:
                return ""

        registrants = []
        for title, obj in whois.get('objects', {}).items():
            if obj.get('contact') is None:
                continue
            if 'registrant' in obj.get('roles', []):
                registrants.append(f"{obj['contact'].get('name')} ({title})")
                break

        return ', '.join(registrants)

    def build_open_ports_table_jira(self, perms):
        open_partly = any([perm['status'] == 'open_partly' for perm in perms])

        open_port_details = "||From Port||To Port||Protocol||CIDR||"
        if open_partly:
            open_port_details += "Registrant||"
        open_port_details += "\n"

        for open_port in perms:
            open_port_details += f"|{open_port['from_port']}|{open_port['to_port']}|{open_port['protocol']}|{open_port['cidr']}|"
            if open_partly:
                if open_port['status'] == 'open_partly':
                    open_port_details += empty_converter(self.get_registrant(open_port['cidr'])) + "|"
                else:
                    open_port_details += "-" + "|"
            open_port_details += "\n"
        return open_port_details

    def build_open_ports_table_slack(self, perms):
        open_port_details = "```\n"

        for open_port in perms:
            if open_port['from_port'] == open_port['to_port']:
                port_protocol = f"{open_port['to_port']}"
            else:
                port_protocol = f"{open_port['from_port']}-{open_port['to_port']}"
            port_protocol += f"/{open_port['protocol']}"

            open_port_details += f"{port_protocol:15}\t{open_port['cidr']}"

            if open_port['status'] == 'open_partly':
                open_port_details += " [" + empty_converter(self.get_registrant(open_port['cidr'])) + "]"

            open_port_details += "\n"

        open_port_details += "```"
        return open_port_details

    def build_instances_table(self, iam_client, instances):
        instance_details = ""
        instance_profile_details = []
        # security group has associated instances
        in_use = False
        # security group has associated instances with public ip in public subnet
        public = False
        # security group has associated instances with public ip in private subnet
        blind_public = False
        owners = []
        bus = []
        products = []
        separator = "\n"

        table_limit_reached = False
        if len(instances) > 0:
            in_use = True
            instance_details += (
                f"||Instance ID||State"
                f"||Private Ip Address||Public Ip Address"
                f"||Owner||Business unit||Product||Component"
                f"||Subnet||\n")

            for ec2_instance in instances:
                if len(ec2_instance.public_ips) > 0:
                    if ec2_instance.public_subnet:
                        public = True
                    else:
                        blind_public = True
                owner = ec2_instance.tags.get('owner')
                bu = ec2_instance.tags.get('bu')
                product = ec2_instance.tags.get('product')
                component = ec2_instance.tags.get('component')
                if self.config.jira.text_field_character_limit == 0 or \
                   len(instance_details) < (self.config.jira.text_field_character_limit * 0.5):
                    instance_details += (
                        f"|{ec2_instance.id}|{ec2_instance.state}"
                        f"|{list_converter(ec2_instance.private_ips)}"
                        f"|{list_converter(ec2_instance.public_ips)}"
                        f"|{empty_converter(owner)}"
                        f"|{empty_converter(bu)}"
                        f"|{empty_converter(product)}"
                        f"|{empty_converter(component)}"
                        f"|{'public' if ec2_instance.public_subnet else 'private'}|\n"
                    )

                    instance_profile_id = ec2_instance.iam_profile_id
                    if instance_profile_id is not None:
                        try:
                            public_role_policies = IAMOperations.get_instance_profile_policy_details(iam_client, instance_profile_id)
                        except Exception:
                            logging.exception("Failed to get instance profile policy details")
                            public_role_policies = []
                        if len(public_role_policies) > 0:
                            for public_role in public_role_policies:
                                instance_profile_details.append(
                                    f"|{ec2_instance.id}|{public_role.role_name}"
                                    f"|{public_role.policy_name}"
                                    f"|{list_converter(public_role.actions, separator)}|\n"
                                )
                elif not table_limit_reached:
                    table_limit_reached = True
                owners.append(owner)
                bus.append(bu)
                products.append(product)

            instance_details = f"*Ec2 Instances{' (limited subset)' if table_limit_reached else ''}*:\n{instance_details}"

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

        if len(instance_profile_details) > 0:
            instance_profile_details = (
                f"\n*Instance Role Unsafe Policies:*\n"
                f"||Instance Id||Role Name||Policy Name||Unsafe actions||\n"
            ) + "".join(instance_profile_details) + "\n"

        return instance_details, instance_profile_details, in_use, public, blind_public, owner, bu, product

    @staticmethod
    def build_rds_instances_table(rds_instances):
        in_use = False
        rds_instance_details = ""

        if len(rds_instances) > 0:
            in_use = True
            rds_instance_details += (
                f"\n*RDS instances:*\n"
                f"||RDS Instance ID||Engine"
                f"||RDS Instance Status"
                f"||Publicly Accessible||\n")
            for rds_instance in rds_instances:
                rds_instance_details += (
                    f"|{rds_instance.id}|{rds_instance.engine}|{rds_instance.status}"
                    f"|{bool_converter(rds_instance.public)}|\n"
                )

        return rds_instance_details, in_use

    @staticmethod
    def build_elb_instances_table(elb_details):
        elb_instance_details = ""
        in_use = False

        if len(elb_details) > 0:
            in_use = True
            elb_instance_details += (
                f"\n*ELB Instances:*\n"
                f"||Load Balance Name||Scheme||ELB Type||Instances||\n")
            for elb in elb_details:
                elb_instance_details += (
                    f"|{elb.id}|{elb.scheme}"
                    f"|{elb.elb_type}|{list_converter(elb.instances)}|\n"
                )

        return elb_instance_details, in_use

    def create_tickets_securitygroups(self):
        """ Class function to create jira tickets """
        table_name = self.config.sg.ddb_table_name

        main_account = Account(region=self.config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(table_name)
        jira = JiraReporting(self.config)
        slack = SlackNotification(self.config)

        for account_id, account_name in self.config.sg.accounts.items():
            logging.debug(f"Checking '{account_name} / {account_id}'")
            issues = IssueOperations.get_account_not_closed_issues(ddb_table, account_id, SecurityGroupIssue)
            for issue in issues:
                group_id = issue.issue_id
                group_name = issue.issue_details.name
                group_region = issue.issue_details.region
                group_vpc_id = issue.issue_details.vpc_id
                tags = issue.issue_details.tags
                # issue has been already reported
                if issue.timestamps.reported is not None:
                    owner = issue.jira_details.owner
                    bu = issue.jira_details.business_unit
                    product = issue.jira_details.product

                    if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                        logging.debug(f"Closing {issue.status.value} security group '{group_name} / {group_id}' issue")

                        comment = (f"Closing {issue.status.value} security group '{group_name} / {group_id}' issue "
                                   f"in '{account_name} / {account_id}' account, '{group_region}' region")
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
                        logging.debug(f"Updating security group '{group_name} / {group_id}' issue")

                        comment = "Issue details are changed, please check again.\n"
                        comment += self.build_open_ports_table_jira(issue.issue_details.perms)
                        comment += JiraOperations.build_tags_table(tags)
                        jira.update_issue(
                            ticket_id=issue.jira_details.ticket,
                            comment=comment
                        )
                        slack.report_issue(
                            msg=f"Security group '{group_name} / {group_id}' issue is changed "
                                f"in '{account_name} / {account_id}' account, '{group_region}' region"
                                f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}"
                                f"\n"
                                f"{self.build_open_ports_table_slack(issue.issue_details.perms)}",
                            owner=owner,
                            account_id=account_id,
                            bu=bu, product=product,
                        )
                        IssueOperations.set_status_updated(ddb_table, issue)
                    else:
                        logging.debug(f"No changes for '{group_name} / {group_id}'")
                # issue has not been reported yet
                else:
                    logging.debug(f"Reporting security group '{group_name} / {group_id}' issue")

                    status = RestrictionStatus(issue.issue_details.status)
                    # if owner/bu/product tags exist on security group - use it
                    group_owner = tags.get("owner", None)
                    group_bu = tags.get("bu", None)
                    group_product = tags.get("product", None)

                    open_port_details = self.build_open_ports_table_jira(issue.issue_details.perms)

                    account_details = (f"*Risk*: High\n\n"
                                       f"*Account Name*: {account_name}\n"
                                       f"*Account ID*: {account_id}\n"
                                       f"*SG Name*: {group_name}\n"
                                       f"*SG ID*: {group_id}\n"
                                       f"*Region*: {group_region}\n")

                    account_details += f"*VPC*: {group_vpc_id}\n\n" if group_vpc_id else "\n"

                    account = Account(id=account_id,
                                      name=account_name,
                                      region=group_region,
                                      role_name=self.config.aws.role_name_reporting)
                    ec2_client = account.client("ec2") if account.session is not None else None

                    sg_instance_details = ec2_owner = ec2_bu = ec2_product = None
                    sg_in_use = sg_in_use_ec2 = sg_in_use_elb = sg_in_use_rds = None
                    sg_public = sg_blind_public = False

                    rds_client = account.client("rds") if account.session is not None else None
                    elb_client = account.client("elb") if account.session is not None else None
                    elbv2_client = account.client("elbv2") if account.session is not None else None

                    iam_client = account.client("iam") if account.session is not None else None

                    rds_instance_details = elb_instance_details = None

                    if ec2_client is not None:
                        ec2_instances = EC2Operations.get_instance_details_of_sg_associated(ec2_client, group_id)
                        sg_instance_details, instance_profile_details,\
                            sg_in_use_ec2, sg_public, sg_blind_public, \
                            ec2_owner, ec2_bu, ec2_product = self.build_instances_table(iam_client, ec2_instances)

                    if elb_client is not None and elbv2_client is not None:
                        try:
                            elb_instances = EC2Operations.get_elb_details_of_sg_associated(elb_client, elbv2_client, group_id)
                            elb_instance_details, sg_in_use_elb = self.build_elb_instances_table(elb_instances)
                        except Exception:
                            logging.exception(f"Failed to build ELB details for '{group_name} / {group_id}' in {account}")

                    if rds_client is not None:
                        try:
                            rds_instances = RDSOperations.get_rds_instance_details_of_sg_associated(rds_client, group_id)
                            rds_instance_details, sg_in_use_rds = self.build_rds_instances_table(rds_instances)
                        except Exception:
                            logging.exception(f"Failed to build RDS details for '{group_name} / {group_id}' in {account}")

                    sg_in_use = sg_in_use_ec2 or sg_in_use_elb or sg_in_use_rds

                    owner = group_owner if group_owner is not None else ec2_owner
                    bu = group_bu if group_bu is not None else ec2_bu
                    product = group_product if group_product is not None else ec2_product

                    if bu is None:
                        bu = self.config.get_bu_by_name(group_name)

                    source_description = f"has {status.value} status"
                    if status == RestrictionStatus.OpenCompletely:
                        source_description = "allows access from any IP address (0.0.0.0/0, ::/0)"
                    elif status == RestrictionStatus.OpenPartly:
                        source_description = "allows access from some definite public ip addresses or networks"

                    if sg_public:
                        priority = "Critical"
                        summary_status = "Internet"
                        issue_description = (f"Security group has EC2 instances in public subnets "
                                             f"with public IP address attached and "
                                             f"{source_description} "
                                             f"for following ports:\n")
                        threat = (
                            f"*Threat*: "
                            f"Instances associated with this security group are accessible via public route over Internet and "
                            f"have ingress rules which allows access to critical services which should be accessible "
                            f"only from VPN or Direct Connect. Accessing these instances via Internet can lead to leakage "
                            f"to third parties of login credentials for such services as databases/remote access."
                            f"Open and Unrestricted access from Internet increases opportunities for "
                            f"malicious activity from public internet which can potentially result into "
                            f"hacking, denial-of-service attacks, loss of data, etc. This also provides "
                            f"an ingress point to the attackers to gain backdoor access within the other "
                            f"critical services.\n"
                        )
                    elif sg_blind_public:
                        priority = "Critical"
                        summary_status = "Internet"
                        issue_description = (f"Security group has EC2 instances in private subnets "
                                             f"with public IP address attached and "
                                             f"{source_description} "
                                             f"for following ports:\n")
                        threat = (f"*Threat*: "
                                  f"Instances listed below can be probed by external attack vectors and "
                                  f"make them vulnerable to blind injection based attacks, as although "
                                  f"the EC2 instances is in a private subnet, if security group and NACL "
                                  f"are allowing access from the internet incoming, traffic will reach "
                                  f"instances when someone is probing the public IP of the instances. "
                                  f"However, there will be no return traffic due to the lack of an IGW.\n")
                    elif not sg_in_use:
                        priority = "Minor"
                        summary_status = "Unused"
                        issue_description = (f"Security group has no EC2 instances attached and "
                                             f"{source_description} "
                                             f"for following ports:\n")
                        threat = (f"*Threat*: "
                                  f"An unused SG can be leveraged to gain control/access within the network "
                                  f"if attached to any exposed instance. This unrestricted access increases "
                                  f"opportunities for malicious activity (hacking, denial-of-service attacks, "
                                  f"loss of data).\n")
                    else:
                        priority = "Major"
                        summary_status = "Intranet"
                        issue_description = (
                            f"Security group has EC2 instances in in private subnets and "
                            f"{source_description} "
                            f"for following ports:\n")
                        threat = (f"*Threat*: "
                                  f"Open access within the network not only provides unrestricted access to "
                                  f"other servers but increases opportunities for malicious activity (hacking, "
                                  f"denial-of-service attacks, loss of data) if attacker gains access to the "
                                  f"services within the network, thus providing lateral movement.\n")

                    tags_table = JiraOperations.build_tags_table(tags)

                    issue_description = (
                        f"{issue_description}"
                        f"{open_port_details}"
                        f"{threat}"
                        f"{account_details}")

                    if status == RestrictionStatus.OpenCompletely:
                        auto_remediation_date = (self.config.now + self.config.sg.issue_retention_date).date()
                        issue_description += f"\n{{color:red}}*Auto-Remediation Date*: {auto_remediation_date}{{color}}\n\n"

                    issue_description += f"{tags_table}"

                    issue_description += f"{sg_instance_details if sg_instance_details else ''}"

                    issue_description += f"{rds_instance_details if rds_instance_details else ''}"

                    issue_description += f"{elb_instance_details if elb_instance_details else ''}"

                    issue_description += f"{instance_profile_details if instance_profile_details else ''}"

                    issue_description += (
                        f"*Recommendation*: "
                        f"Allow access only for a minimum set of required ip addresses/ranges from [RFC1918|https://tools.ietf.org/html/rfc1918]. "
                    )

                    if self.config.whitelisting_procedure_url:
                        issue_description += (f"For any other exceptions, please follow the [whitelisting procedure|{self.config.whitelisting_procedure_url}] "
                                              f"and provide a strong business reasoning. ")

                    issue_description += f"Be sure to delete overly permissive rules after creating rules that are more restrictive.\n"

                    issue_summary = (f"{summary_status} open security group '{group_name}'"
                                     f" in '{account_name} / {account_id}' account{' [' + bu + ']' if bu else ''}")

                    try:
                        response = jira.add_issue(
                            issue_summary=issue_summary, issue_description=issue_description,
                            priority=priority, labels=["insecure-services"],
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

                    issue.jira_details.public = sg_public
                    issue.jira_details.blind_public = sg_blind_public
                    issue.jira_details.in_use = sg_in_use
                    issue.jira_details.owner = owner
                    issue.jira_details.business_unit = bu
                    issue.jira_details.product = product

                    slack.report_issue(
                        msg=f"Discovered {issue_summary}"
                            f"{' (' + jira.ticket_url(issue.jira_details.ticket) + ')' if issue.jira_details.ticket else ''}"
                            f"\n"
                            f"{self.build_open_ports_table_slack(issue.issue_details.perms)}",
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
        obj = CreateSecurityGroupsTickets(config)
        obj.create_tickets_securitygroups()
    except Exception:
        logging.exception("Failed to create security group tickets")
