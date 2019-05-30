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

class ElasticSearchOperations:
    @classmethod
    @timeit
    def get_elasticsearch_details_of_sg_associated(cls, elasticsearch_client, group_id):
        """ Retrieve elastic search details meta data with security group attached

        :param elasticsearch_client: boto3 elastic search client
        :param group_id: security group id

        :return: list with elastic search details
        """
        # describe elastic search details with security group attached
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