import boto3
import logging
import moto

from moto import mock_ec2
from moto.ec2.exceptions import InvalidPermissionNotFoundError
from library.utility import jsonDumps


def start():
    """
    Entrypoint for mocking EC2.
    :return: nothing
    """
    # start EC2 mocking with moto
    mock = mock_ec2()
    mock.start()
    #print(jsonDumps(ec2.describe_security_groups()))
    """ Monkey-patching of moto """
    # create new function to find rule by cidr in ip_ranges
    moto.ec2.models.SecurityRule.match = security_rule_match
    # create new function to remove cidr from ip_ranges
    moto.ec2.models.SecurityRule.remove_cidr = security_rule_match_remove_cidr
    # save original revoke_security_group_ingress function to reuse in patched
    moto.ec2.models.SecurityGroupBackend.revoke_security_group_ingress_original = \
        moto.ec2.models.SecurityGroupBackend.revoke_security_group_ingress
    # replace original function with patched one
    moto.ec2.models.SecurityGroupBackend.revoke_security_group_ingress = revoke_security_group_ingress_patched
    """ Monkey-patching is done """

def create_env(secgroups, region):
    logging.debug(f"======> creating new EC2 env from {jsonDumps(secgroups)}")
    ec2_client = boto3.client("ec2", region_name=region)

    for secgroup, rule in secgroups.items():
        groupId = ec2_client.create_security_group(
                GroupName=secgroup,
                VpcId="vpc-12345678",
                Description=secgroup,
        )['GroupId']

        secgroups[secgroup]["Id"] = groupId
        if "IpProtocol" not in rule:
            # empty security group rule
            continue

        perms = [
            { "IpRanges": [{'CidrIp': ipRange} for ipRange in rule.get("IpRanges", [])],
              # it seems that moto does not support Ipv6Ranges
              "Ipv6Ranges": [{'CidrIpv6': ipRange} for ipRange in rule.get("Ipv6Ranges", [])],
              "UserIdGroupPairs": [{'GroupName': rule.get("UserIdGroupPairs", "")}],
              "IpProtocol": rule["IpProtocol"]
            }
        ]
        if "FromPort" in rule:
            perms[0]["FromPort"] = rule["FromPort"]
        if "ToPort" in rule:
            perms[0]["ToPort"] = rule["ToPort"]
        ec2_client.authorize_security_group_ingress(
            GroupId=groupId,
            IpPermissions=perms,
        )

    secgroups = ec2_client.describe_security_groups(DryRun=False)["SecurityGroups"]
    for group in secgroups:
        if group['GroupName'] == 'default':
            ec2_client.delete_security_group(GroupId=group['GroupId'])
    logging.debug(f"{jsonDumps(secgroups)}")

def security_rule_match(self, ip_protocol, from_port, to_port, cidr):
    return self.ip_protocol == ip_protocol and \
           self.from_port == from_port and \
           self.to_port == to_port and \
           cidr in self.ip_ranges

def security_rule_match_remove_cidr(self, cidr):
    if cidr in self.ip_ranges:
        self.ip_ranges.remove(cidr)

def revoke_security_group_ingress_patched(self,
                                          group_name_or_id,
                                          ip_protocol,
                                          from_port,
                                          to_port,
                                          ip_ranges,
                                          source_group_names=None,
                                          source_group_ids=None,
                                          vpc_id=None):
    try:
        self.revoke_security_group_ingress_original(group_name_or_id,
                                                    ip_protocol,
                                                    from_port,
                                                    to_port,
                                                    ip_ranges,
                                                    source_group_names,
                                                    source_group_ids,
                                                    vpc_id)
    except InvalidPermissionNotFoundError:
        ip_ranges = ip_ranges
        if len(ip_ranges) == 1:
            group = self.get_security_group_by_name_or_id(group_name_or_id,
                                                          vpc_id)
            cidr = ip_ranges[0]
            for rule in group.ingress_rules:
                if rule.match(ip_protocol,
                              from_port,
                              to_port,
                              cidr):
                    rule.remove_cidr(cidr)
                    return rule
        raise