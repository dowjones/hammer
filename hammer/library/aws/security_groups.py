import json
import logging
import ipaddress

from enum import Enum
from datetime import datetime, timezone
from botocore.exceptions import ClientError
from library.utility import jsonDumps
from library.aws.s3 import S3Operations
from library.aws.utility import convert_tags


class RestrictionStatus(Enum):
    Restricted = "restricted"
    OpenCompletely = "open_completely"
    OpenPartly = "open_partly"


class SecurityGroupOperations:
    @staticmethod
    def backup_s3(account,
                  s3_client, bucket,
                  source):
        """
        Backup given security group json to S3

        :param account: `Account` instance
        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup
        :param source: security group json

        :return: S3 path (without bucket name) to saved object with security group backup
        """
        group_id = source["GroupId"]
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        # this prefix MUST match prefix in find_source_s3
        prefix = f"security_groups/{account.id}/{account.region}/"
        path = (f"{prefix}"
                f"{group_id}_{timestamp}.json")
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, source)
        return path

    @staticmethod
    def find_source_s3(account,
                       s3_client, bucket,
                       group_id):
        """
        Find the most recent backup for security group on S3

        :param account: `Account` instance
        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup
        :param group_id: security group id to search for

        :return: dict with security group properties (as AWS returns in `describe_security_groups`)
        """
        # this prefix MUST match prefix in backup_s3
        prefix = f"security_groups/{account.id}/{account.region}/"
        objects = s3_client.list_objects(
            Bucket=bucket,
            Prefix=prefix
        ).get('Contents')
        if objects is None:
            logging.error(f"Failed to find '{group_id}' rules backup in {account}")
            return
        backup_objects = [ obj["Key"] for obj in objects if obj.get("Key", "").startswith(f"{prefix}{group_id}_") ]
        # return most recent backup
        recent_backup = max(backup_objects)
        source = json.loads(S3Operations.get_object(s3_client, bucket, recent_backup))
        assert group_id == source["GroupId"]
        return source

    @classmethod
    def restore_s3(cls,
                   account,
                   s3_client, bucket,
                   ec2_client, group_id):
        """
        Add all ingress rules from backup to security group.
        It does not check if rule already exists (that is handled in `add_inbound_rule`)

        :param account: `Account` instance
        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup
        :param ec2_client: EC2 boto3 client
        :param group_id: security group id to search for

        :return: nothing
        """
        source = cls.find_source_s3(
            account,
            s3_client, bucket,
            group_id
        )
        # TODO: remove existing permissions?
        for ingress in source["IpPermissions"]:
            from_port = ingress.get("FromPort", None)
            to_port = ingress.get("ToPort", None)
            ip_protocol = ingress["IpProtocol"]
            cidrs = [ ipv6_range["CidrIpv6"] for ipv6_range in ingress.get("Ipv6Ranges", []) ]
            cidrs += [ ip_range["CidrIp"] for ip_range in ingress.get("IpRanges", []) ]
            for cidr in cidrs:
                cls.add_inbound_rule(ec2_client, group_id, ip_protocol, from_port, to_port, cidr)

    @staticmethod
    def ip_permissions(ip_protocol, from_port, to_port, cidr):
        """
        Construct `IpPermissions` element (dict) as AWS expects to see in `authorize_security_group_*`.
        Automatically detects if cidr IPv4 or IPv6 address/range.

        :param ip_protocol: The IP protocol name (tcp, udp, icmp) or number
        :param from_port: The start of port range
        :param to_port: The end of port range
        :param cidr: The CIDR range (accept both IPv4 and IPv6)

        :return: dict with `IpPermissions` element
        """
        perms = { 'IpProtocol': ip_protocol }
        if from_port is not None and \
           to_port is not None:
            perms['FromPort'] = from_port
            perms['ToPort'] = to_port
        ipv = ipaddress.ip_network(cidr).version
        if ipv == 4:
            perms['IpRanges'] = [{'CidrIp': cidr}]
        else:
            perms['Ipv6Ranges'] = [{'CidrIpv6': cidr}]
        return perms

    @classmethod
    def add_inbound_rule(cls, ec2_client, group_id, ip_protocol, from_port, to_port, cidr):
        """
        Add ingress rule to security group

        :param ec2_client: EC2 boto3 client
        :param group_id: security group id to add rules to
        :param ip_protocol: The IP protocol name (tcp, udp, icmp) or number
        :param from_port: The start of port range
        :param to_port: The end of port range
        :param cidr: The CIDR range (accept both IPv4 and IPv6)

        :return: nothing, can raise exception
        """
        logging.debug(f"Adding inbound rule to '{group_id}' "
                      f"[Protocol={ip_protocol}, "
                      f"Ports={from_port}-{to_port}, "
                      f"Cidr={cidr}]")
        try:
            ec2_client.authorize_security_group_ingress(
                DryRun=False,
                GroupId=group_id,
                IpPermissions=[cls.ip_permissions(ip_protocol, from_port, to_port, cidr)]
            )
        except ClientError as err:
            if err.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                pass
            else:
                raise

    @classmethod
    def add_inbound_rules_rfc1918(cls, ec2_client, group_id, ip_protocol, from_port, to_port):
        """
        Add ingress rules to security group with source CIDRs from RFC1918

        :param ec2_client: EC2 boto3 client
        :param group_id: security group id to add rules to
        :param ip_protocol: The IP protocol name (tcp, udp, icmp) or number
        :param from_port: The start of port range
        :param to_port: The end of port range

        :return: nothing
        """
        ip_ranges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        for cidr in ip_ranges:
            cls.add_inbound_rule(ec2_client, group_id, ip_protocol, from_port, to_port, cidr)

    @classmethod
    def remove_inbound_rule(cls, ec2_client, group_id, ip_protocol, from_port, to_port, cidr):
        """
        Remove ingress rule from security group

        :param ec2_client: EC2 boto3 client
        :param group_id: security group id to remove rules from
        :param ip_protocol: The IP protocol name (tcp, udp, icmp) or number
        :param from_port: The start of port range
        :param to_port: The end of port range
        :param cidr: The CIDR range (accept both IPv4 and IPv6)

        :return: nothing
        """
        logging.debug(f"Removing inbound rule from '{group_id}' "
                      f"[Protocol={ip_protocol}, "
                      f"Ports={from_port}-{to_port}, "
                      f"Cidr={cidr}]")
        ec2_client.revoke_security_group_ingress(
            DryRun=False,
            GroupId=group_id,
            IpPermissions=[cls.ip_permissions(ip_protocol, from_port, to_port, cidr)]
        )

    @classmethod
    def restrict(cls, ec2_client, group_name, group_id, protocol, from_port, to_port, cidr):
        """
        Replace source CIDR in ingress rule with CIDRs from RFC1918

        :param ec2_client: EC2 boto3 client
        :param group_name: security group name to remove rules from (for logging purpose)
        :param group_id: security group id to remove rules from
        :param protocol: The IP protocol name (tcp, udp, icmp) or number
        :param from_port: The start of port range
        :param to_port: The end of port range
        :param cidr: The CIDR range (accept both IPv4 and IPv6) to replace with CIDRs from RFC1918

        :return: nothing
        """
        logging.debug(f"Restricting '{group_name}' ({group_id}) "
                      f"[Protocol={protocol}, "
                      f"Ports={from_port}-{to_port}, "
                      f"Cidr={cidr}"
                      f"] with source RFC1918 IP ranges")
        cls.add_inbound_rules_rfc1918(
            ec2_client,
            group_id,
            protocol,
            from_port, to_port)
        cls.remove_inbound_rule(
            ec2_client,
            group_id,
            protocol,
            from_port, to_port,
            cidr)


class IPRange(object):
    """
    Basic class for security group CIDR range.
    Encapsulates CIDR and boolean marker if CIDR restricted or not.
    """
    def __init__(self, cidr):
        self.cidr = cidr
        # by default assume that CIDR is restricted,
        # this later can be changed during security group check
        self.status = RestrictionStatus.Restricted

    @property
    def restricted(self):
        """
        :return: boolean, True - if IPRange element is restricted
                          False - otherwise
        """
        return self.status == RestrictionStatus.Restricted

    def __str__(self):
        return self.cidr


class SecurityGroupPermission(object):
    """
    Basic class for security group `IpPermissions`.
    Encapsulates `IpProtocol`/`FromPort`/`ToPort` and list of `IpRanges`.
    """
    def __init__(self, group, ingress):
        """
        :param group: `SecurityGroup` instance which contains this `IpPermissions` (to be able to perform operations against it)
        :param ingress: single `IpPermissions` element as AWS returns
        """
        self.group = group
        # The IP protocol name (tcp, udp, icmp) or number
        self.protocol = ingress["IpProtocol"]
        # When authorizing security group rules, specifying -1 or a protocol number other than
        # tcp, udp, icmp or 58 (ICMPv6) allows traffic on all ports,
        # regardless of any port range you specify
        # For 58 (ICMPv6), you can optionally specify a port range;
        # if you don't, traffic for all types and codes is allowed when authorizing rules.
        if self.protocol == "-1" or \
           self.protocol not in ["tcp", "udp", "icmp", "icmpv6", "58"]:
            self.from_port = None
            self.to_port = None
        else:
            # Port range for the TCP and UDP protocols,
            # or an ICMP/ICMPv6 type number.
            # A value of -1 indicates all ICMP/ICMPv6 types.
            self.from_port = ingress.get("FromPort", 0)
            self.to_port = ingress.get("ToPort", 65535)

        # as it does not matter if range IPv4 or IPv6 - add all them to single list
        self.ip_ranges = [IPRange(ip_range["CidrIp"]) for ip_range in ingress["IpRanges"]]
        self.ip_ranges += [IPRange(ip_range["CidrIpv6"]) for ip_range in ingress.get("Ipv6Ranges", [])]

        # list with another security groups (restriction by security group but not by IpRanges)
        # userid_group_pairs = ingress["UserIdGroupPairs"]

    def __str__(self):
        ip_ranges = ", ".join([str(ip_range) for ip_range in self.ip_ranges])
        ports = f"Port={self.from_port}" if self.from_port == self.to_port else f"Ports={self.from_port}-{self.to_port}"
        return f"{self.__class__.__name__}(Protocol={self.protocol}, {ports}, IPRanges=[{ip_ranges}])"

    @property
    def status(self):
        """
        :return: the worst RestrictionStatus among permissions (OpenCompletely -> OpenPartly -> Restricted)
        """
        statuses = {ip_range.status for ip_range in self.ip_ranges}
        if RestrictionStatus.OpenCompletely in statuses:
            return RestrictionStatus.OpenCompletely
        elif RestrictionStatus.OpenPartly in statuses:
            return RestrictionStatus.OpenPartly
        return RestrictionStatus.Restricted

    @property
    def restricted(self):
        """
        :return: boolean, True - if all `IPRange` elements for this `SecurityGroupPermission` are restricted
                          False - otherwise
        """
        return all(ip_range.restricted for ip_range in self.ip_ranges)

    def restrict(self, status=None):
        """
        Restrict all not restricted `IPRange` elements

        :param status: restrict only permissions with given RestrictionStatus

        :return: number of restricted ip ranges

        .. note:: It does not change `status` for processed `IPRange`.
                  You need to recheck security group to ensure that it was really restricted.
        """
        processed = 0
        for ip_range in self.ip_ranges:
            if (status is not None and ip_range.status == status) or \
               (status is None and not ip_range.restricted):
                SecurityGroupOperations.restrict(
                    self.group.account.client("ec2"),
                    self.group.name,
                    self.group.id,
                    self.protocol,
                    self.from_port, self.to_port,
                    ip_range.cidr)
                processed += 1
        return processed


class SecurityGroup(object):
    """
    Basic class for security group.
    Encapsulates `GroupName`/`GroupId`/`Tags` and list of `IpPermissions`.
    """
    def __init__(self, account, source):
        """
        :param account: `Account` instance where security group is present
        :param source: single `SecurityGroups` element as AWS returns
        """
        self.account = account
        self.source = source
        self.name = self.source["GroupName"]
        self.id = self.source["GroupId"]
        self.vpc_id = self.source.get("VpcId", None)
        self.tags = convert_tags(source.get('Tags', []))
        # list with all `SecurityGroupPermission` elements
        self.permissions = []
        self.permissions_source = self.source["IpPermissions"]

        # transform all `IpPermissions` elements to `SecurityGroupPermission` instances
        for ingress in self.permissions_source:
            perm = SecurityGroupPermission(self, ingress)
            self.permissions.append(perm)

    def __str__(self):
        perms = ", ".join([str(perm) for perm in self.permissions])
        return f"{self.__class__.__name__}(Name={self.name}, Id={self.id}, Permissions=[{perms}])"

    def restriction_status(self, cidr):
        """
        Check restriction status of cidr

        :param cidr: string with IPv4 or IPv6 address/subnet

        :return: RestrictionStatus with check result
        """
        status = RestrictionStatus.Restricted
        if cidr.endswith("/0"):
            status = RestrictionStatus.OpenCompletely
        elif ipaddress.ip_network(cidr).is_global:
            status = RestrictionStatus.OpenPartly
        logging.debug(f"Checked '{cidr}' - '{status.value}'")
        return status

    def check(self, restricted_ports):
        """
        Walk through all `SecurityGroupPermission` and mark not restricted elements.

        :param restricted_ports: list with ports to consider `SecurityGroupPermission` as not restricted

        :return: nothing
        """
        logging.debug(f"Checking security group '{self.name}' ({self.id})\n{jsonDumps(self.permissions_source)}")
        if len(self.permissions) == 0:
            logging.debug(f"Skipping empty security group '{self.name}' ({self.id})")
            return

        for perm in self.permissions:
            for ip_range in perm.ip_ranges:
                logging.debug(f"Checking '{perm.protocol}' '{perm.from_port}-{perm.to_port}' ports for {ip_range}")
                # first condition - CIDR is Global/Public
                status = self.restriction_status(ip_range.cidr)
                if status == RestrictionStatus.Restricted:
                    logging.debug(f"Skipping restricted '{ip_range}'")
                    continue
                # second - check if ports from `restricted_ports` list has intersection with ports from FromPort..ToPort range
                if perm.from_port is None or perm.to_port is None:
                    logging.debug(f"Marking world-wide open all ports from '{ip_range}'")
                    ip_range.status = status
                elif perm.protocol in ["icmp", "icmpv6", "58"]:
                    logging.debug(f"Skipping ICMP '{perm.protocol}' "
                                  f"'{perm.from_port}-{perm.to_port}' types "
                                  f"for {ip_range}")
                elif set(restricted_ports) & set(range(perm.from_port, perm.to_port + 1)):
                    logging.debug(f"Marking world-wide open '{perm.from_port}-{perm.to_port}' "
                                  f"in {restricted_ports} from '{ip_range}'")
                    ip_range.status = status
                else:
                    logging.debug(f"Skipping '{perm.from_port}-{perm.to_port}' not in {restricted_ports}")

    @property
    def status(self):
        """
        :return: the worst RestrictionStatus among permissions (OpenCompletely -> OpenPartly -> Restricted)
        """
        statuses = {perms.status for perms in self.permissions}
        if RestrictionStatus.OpenCompletely in statuses:
            return RestrictionStatus.OpenCompletely
        elif RestrictionStatus.OpenPartly in statuses:
            return RestrictionStatus.OpenPartly
        return RestrictionStatus.Restricted

    @property
    def restricted(self):
        """
        :return: boolean, True - if all `SecurityGroupPermission` elements for this `SecurityGroup` are restricted
                          False - otherwise
        """
        return all(perm.restricted for perm in self.permissions)

    def backup_s3(self, s3_client, bucket):
        """
        Backup security group source (as AWS returns) to S3

        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup

        :return: S3 path (without bucket name) to saved object with security group backup
        """
        return SecurityGroupOperations.backup_s3(
            self.account,
            s3_client, bucket,
            self.source)

    def restrict(self, status=None):
        """
        Restrict all not restricted `SecurityGroupPermission` elements

        :param status: restrict only permissions with given RestrictionStatus

        :return: None (in case of any error)
                 number of processed rules

        .. note:: It does not set `restricted` flag for processed `SecurityGroupPermission`.
                  You need to recheck security group to ensure that it was really restricted.
        """
        processed = 0
        for perm in self.permissions:
            if not perm.restricted:
                try:
                    processed += perm.restrict(status)
                except ClientError as err:
                    if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                        logging.error(f"Access denied in {self.account} "
                                      f"(ec2:{err.operation_name})")
                    else:
                        logging.exception(f"Failed to restrict {str(self)}")
                    return None
        return processed


class SecurityGroupsChecker(object):
    """
    Basic class for checking security group in account/region.
    Encapsulates check settings and discovered security groups.
    """
    def __init__(self,
                 account,
                 restricted_ports):
        """
        :param account: `Account` instance with security groups to check
        :param restricted_ports: list with ports to consider `SecurityGroup` as not restricted
        """
        self.account = account
        self.restricted_ports = restricted_ports
        self.groups = []

    def get_security_group(self, id):
        """
        :return: `SecurityGroup` by id
        """
        for group in self.groups:
            if group.id == id:
                return group
        return None

    def check(self, ids=None, tags=None):
        """
        Walk through security groups in the account/region and check them (restricted or not).
        Put all gathered groups to `self.groups`.

        :param ids: list with security group ids to check, if it is not supplied - all groups must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        args = {'DryRun': False}
        if ids:
            args['GroupIds'] = ids
        if tags:
            args['Filters'] = []
            for key, value in tags.items():
                args['Filters'].append(
                    {'Name': f"tag:{key}", 'Values': value if isinstance(value, list) else [value]},
                )
        try:
            secgroups = self.account.client("ec2").describe_security_groups(**args)["SecurityGroups"]
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(ec2:{err.operation_name})")
            elif err.response['Error']['Code'] == "InvalidGroup.NotFound":
                logging.error(err.response['Error']['Message'])
                return False
            else:
                logging.exception(f"Failed to describe security groups in {self.account}")
            return False

        for security_group in secgroups:
            sg = SecurityGroup(self.account,
                               security_group)
            sg.check(self.restricted_ports)
            self.groups.append(sg)
        return True
