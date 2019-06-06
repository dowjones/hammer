import logging


from botocore.exceptions import ClientError
from collections import namedtuple
from library.utility import timeit


# structure which describes Elastic search domains
ElasticSearchDomain_Details = namedtuple('ElasticSearchDomain', [
    # domain name
    'domain_name',
    # domain arn
    'domain_arn',
    # vpc_id
    'vpc_id'
    ])


class ESDomainDetails(object):
    """
    Basic class for ElasticSearch domain details.

    """

    def __init__(self, account, name, id, arn, is_logging=None, encrypted=None):
        """
        :param account: `Account` instance where ECS task definition is present

        :param name: name of the task definition
        :param arn: arn of the task definition
        :param arn: tags of task definition.
        :param is_logging: logging enabled or not.
        """
        self.account = account
        self.name = name
        self.id = id
        self.arn = arn
        self.is_logging = is_logging
        self.encrypted = encrypted


class ElasticSearchOperations:
    @classmethod
    @timeit
    def get_elasticsearch_details_of_sg_associated(cls, elasticsearch_client, group_id):
        """ Retrieve elastic search details meta data with security group attached

        :param elasticsearch_client: boto3 elastic search client
        :param group_id: security group id

        :return: list with elastic search details
        """
        # describe elastic search domain details with security group attached.
        domains_list = []

        elasticsearch_response = elasticsearch_client.list_domain_names()
        for domain in elasticsearch_response["DomainNames"]:
            domain_name = domain["DomainName"]
            domain_details = elasticsearch_client.describe_elasticsearch_domain(
                DomainName=domain_name
            )["DomainStatus"]
            if group_id in str(domain_details):
                domains_list.append(ElasticSearchDomain_Details(
                    domain_name=domain_name,
                    domain_arn=domain_details["ARN"],
                    vpc_id=domain_details["VPCOptions"]["VPCId"]
                ))

        return domains_list


class ESDomainChecker:
    """
        Basic class for checking EBS snapshots in account/region.
        Encapsulates discovered EBS snapshots.
        """

    def __init__(self, account):
        """
        :param account: `Account` instance with Elasticsearch domains to check
        """
        self.account = account
        self.domains = []

    def get_domain(self, id):
        """
        :return: `EBSSnapshot` by id
        """
        for domain in self.domains:
            if domain.id == id:
                return domain
        return None

    def check(self, ids=None):
        """
        Walk through Elasticsearch domains in the account/region and put them to `self.domains`.

        :param ids: list with Elasticsearch domain ids to check, if it is not supplied - all Elasticsearch domains must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            es_client = self.account.client("es")
            if ids is None:
                domain_names_list = es_client.list_domain_names()["DomainNames"]
                for domain_name in domain_names_list:
                    ids.append(domain_name["DomainName"])

            if ids is not None:
                domain_details = es_client.describe_elasticsearch_domains(DomainNames=ids)["DomainStatusList"]

        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(ec2:{err.operation_name})")
            else:
                logging.exception(f"Failed to describe snapshots in {self.account}")
            return False

        domain_encrypted = False
        is_logging = False
        for domain_detail in domain_details:
            domain_name = domain_detail["DomainName"]
            domain_id = domain_detail["DomainId"]
            domain_arn = domain_detail["ARN"]
            if domain_detail["EncryptionAtRestOptions"]["Enabled"] or \
                    domain_detail["NodeToNodeEncryptionOptions"]["Enabled"]:
                domain_encrypted = True

            if domain_detail["LogPublishingOptions"]["Options"]:
                is_logging = True

            domain = ESDomainDetails(self.account,
                                     name=domain_name,
                                     id=domain_id,
                                     arn=domain_arn,
                                     is_logging=is_logging,
                                     encrypted=domain_encrypted)
            self.domains.append(domain)
        return True
