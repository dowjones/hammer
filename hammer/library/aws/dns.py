import logging

from collections import namedtuple
from library.utility import timeit

from botocore.exceptions import ClientError


# structure which describes hosted zones
HosteZones = namedtuple('HostedZone', [
    # hosted zone id
    'id',
    # hosted zone name
    'name',
    # hosted zone type (public or private)
    'type',
    # list with record set
    'cname_record_set'
    ])

class DNSOperations(object):

    @classmethod
    @timeit
    def get_dns_hosted_zone_details(cls, dns_client, domain_name):
        """ Retrieve domain's hosted zone details along with record set

                :param dns_client: boto3 route53 client
                :param domain_name: dns name

                :return: list with hosted zone details
                """
        # describe hosted zones with dns name.
        response = dns_client.list_hosted_zones()
        hosted_zone_details = []
        if "HostedZones" in response:
            for hosted_zone in response["HostedZones"]:
                id = hosted_zone["Id"]
                name= hosted_zone["Name"]
                if domain_name in name:
                    type = hosted_zone["Config"]["PrivateZone"]
                    cname_record_set_list = []
                    record_set_response = dns_client.list_resource_record_sets(
                        HostedZoneId=id
                    )
                    if "ResourceRecordSets" in record_set_response:
                        for resource_record_set in record_set_response["ResourceRecordSets"]:
                            if resource_record_set["Type"] == "CNAME":
                                for record_set in resource_record_set["ResourceRecords"]:
                                    cname_record_set_list.append(record_set["Value"])

                    hosted_zone = HosteZones(
                        id=id,
                        name=name,
                        type=type,
                        cname_record_set=cname_record_set_list
                    )
                    hosted_zone_details.append(hosted_zone)

        return hosted_zone_details


    @staticmethod
    def renew_domain(dns_client, domain_name, year):
        """
        Renew the domain with duration.

        :param dns_client: Route53Domain boto3 client
        :param domain_name: domain name which needs to be renew
        :param year: current year of the domain expiry.

        :return: nothing
        """
        """dns_client.renew_domain(
            DomainName=domain_name,
            DurationInYears=2,
            CurrentExpiryYear=year
        )"""

        dns_client.enable_domain_auto_renew(
            DomainName=domain_name
        )


class Rout53Domain(object):
    """
    Basic class for Route53 Domain.
    Encapsulates domain auto_renew, expiry date.
    """
    def __init__(self, account, name, expiry_date, auto_renew, now, takeover_criteria):
        """
        :param account: `Account` instance where domain

        :param name: `Name` of domain name
        :param expiry_date: Domain expiration date
        :param auto_renew: Domain auto_renew flag        
        :param now: corrent date
        :param takeover_criteria: expiration validate days.
        """
        self.account = account
        self.name =name
        self.auto_renew = auto_renew
        self.expiry_date = expiry_date
        self.now = now
        self.takeover_days = takeover_criteria


    def __str__(self):
        return f"{self.__class__.__name__}(Name={self.name}, IsExpiry={self.validate_expiry})"

    @property
    def validate_expiry(self):
        """
        :return: boolean, True - if domain is going to expiry in 1 month
        """
        return (self.expiry_date - self.now).days < self.takeover_days

    def renew_domain(self):
        """
        Renew the domain.

        :return: nothing
        
        """
        try:
            DNSOperations.renew_domain(self.account.client("route53domains"), self.name, self.now.year)
        except Exception:
            logging.exception(f"Failed to renew domain {self.name}")
            return False

        return True


class DNSTakeoverChecker(object):
    """
    Basic class for checking Domain name expiry details in account.
    Encapsulates discovered Domains.
    """
    def __init__(self, account, now=None, takeover_criteria=None):
        """
        :param account: `Account` instance with Domain name to check
        """
        self.account = account
        self.now = now
        self.takeover_criteria_days = takeover_criteria
        self.domains = []

    def get_domain(self, name):
        """
        :return: `Domain` by name
        """
        for domain in self.domains:
            if domain.name == name:
                return domain
        return None

    def check(self, domains=None):
        """
        Walk through Domains  in the account and check them (expiry soon or not).
        Put all gathered domains to `self.domains`.

        :param domains: list with Domains names to check, if it is not supplied - all domains must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering dirung list, so get all domains for account
            response = self.account.client("route53domains").list_domains()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(dns:{err.operation_name})")
            else:
                logging.exception(f"Failed to list domains in {self.account}")
            return False

        if "Domains" in response:
            for domain in response["Domains"]:
                domain_name = domain["DomainName"]
                expiry_date = domain["Expiry"]
                auto_renew = domain["AutoRenew"]

                if domains is not None and domain_name not in domains:
                    continue

                if not auto_renew:
                    domain = Rout53Domain(account=self.account,
                                        name=domain_name,
                                        expiry_date=expiry_date,
                                        auto_renew= auto_renew,
                                        now = self.now,
                                        takeover_criteria = self.takeover_criteria_days)
                    self.domains.append(domain)
        return True
