import json
import logging
import pathlib
import os


from copy import deepcopy


class PolicyOperations(object):
    @staticmethod
    def public_statement(statement):
        """
        Check if supplied policy statement allows public access.

        :param statement: dict with policy statement (as AWS returns)

        :return: boolean, True - if statement allows access from '*' `Principal`, not restricted by `IpAddress` condition
                          False - otherwise
        """
        effect = statement['Effect']
        principal = statement.get('Principal', {})
        not_principal = statement.get('NotPrincipal', None)
        condition = statement.get('Condition', None)
        suffix = "/0"
        # check both `Principal` - `{"AWS": "*"}` and `"*"`
        # and condition (if exists) to be restricted (not "0.0.0.0/0")
        if effect == "Allow" and \
                (principal == "*" or principal.get("AWS") == "*"):
            if condition is not None:
                if suffix in str(condition.get("IpAddress")):
                    return True
            else:
                return True
        if effect == "Allow" and \
                        not_principal is not None:
            # TODO: it is not recommended to use `Allow` with `NotPrincipal`, need to write proper check for such case
            # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
            logging.error(f"TODO: is this statement public???\n{statement}")
        return False

    @classmethod
    def public_policy(cls, policy):
        """
        Check if supplied  policy allows public access by checking policy statements

        :param policy: dict with policy (as AWS returns)

        :return: boolean, True - if any policy statement has public access allowed
                          False - otherwise
        """
        for statement in policy.get("Statement", []):
            if cls.public_statement(statement):
                return True
        return False

    @classmethod
    def restrict_policy(cls, policy):
        """
        Walk through policy and restrict all public statements.
        It does not restrict supplied policy dict, but creates an copy and works with that copy.

        :param policy: dict with policy (as AWS returns)

        :return: new dict with policy based on old one, but with restricted public statements
        """
        # make a copy of supplied policy to restrict it
        new_policy = deepcopy(policy)
        # iterate over policy copy and restrict statements
        for statement in new_policy.get("Statement", []):
            cls.restrict_statement(statement)
        return new_policy

    @classmethod
    def restrict_statement(cls, statement):
        """
        Restricts provided policy statement with RFC1918 condition.
        It performs in-place restriction of supplied statement.

        :param statement: dict with policy statement to restrict (as AWS returns)

        :return: nothing
        """

        suffix = "/0"
        ip_ranges_rfc1918 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        if cls.public_statement(statement):
            # get current condition, if no condition - return condition with source ip from rfc1918
            condition = statement.get('Condition', { "IpAddress": {"aws:SourceIp": ip_ranges_rfc1918}})
            # get current ip addresses from condition, if no ip addresses - return source ip from rfc1918
            ipaddress = condition.get("IpAddress", {"aws:SourceIp": ip_ranges_rfc1918})
            # get source ips, if no ips return rfc1918 range
            sourceip = ipaddress.get("aws:SourceIp", ip_ranges_rfc1918)
            # make list from source ip if it is a single string value
            if isinstance(sourceip, str):
                sourceip = [sourceip]
            # replace cidr with "/0" from source ips with ip ranges from rfc1918
            ip_ranges = []
            for cidr in sourceip:
                if suffix not in cidr:
                    ip_ranges.append(cidr)
                else:
                    ip_ranges += ip_ranges_rfc1918
            # remove dublicates
            ip_ranges = list(set(ip_ranges))
            ipaddress['aws:SourceIp'] = ip_ranges
            condition['IpAddress'] = ipaddress
            statement['Condition'] = condition
