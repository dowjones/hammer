import json
import logging
import pathlib

from datetime import datetime, timezone
from botocore.exceptions import ClientError
from collections import namedtuple
from library.utility import timeit
from library.utility import jsonDumps
from library.aws.utility import convert_tags
from library.aws.s3 import S3Operations

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

    @staticmethod
    def put_domain_policy(es_client, domain_name, policy):
        """
        Replaces a policy on a domain. If the domain already has a policy, the one in this request completely replaces it.

        :param es_client: Elasticsearch boto3 client
        :param domain_name: Elasticsearch domain where to update policy on
        :param policy: `dict` or `str` with policy. `Dict` will be transformed to string using pretty json.dumps().

        :return: nothing
        """
        policy_json = jsonDumps(policy) if isinstance(policy, dict) else policy
        es_client.update_elasticsearch_domain_config(
            DomainName=domain_name,
            AccessPolicies=policy_json,
        )

    def retrieve_loggroup_arn(self, cw_client, domain_name):
        """
        
        :param cw_client: cloudwatch logs boto3 client
        :param domain_name: Elasticsearch domain name
        :return: 
        """
        log_groups = cw_client.describe_log_groups()
        domain_log_group_name = "/aws/aes/domains/" + domain_name + "/application-logs"
        log_group_arn = None
        for log_group in log_groups["logGroups"]:
            log_group_name = log_group["logGroupName"]
            if log_group_name == domain_log_group_name:
                log_group_arn = log_group["arn"]

        if not log_group_arn:
            cw_client.create_log_group(logGroupName=domain_log_group_name)
            self.retrieve_loggroup_arn(cw_client, domain_name)

        return log_group_arn

    def set_domain_logging(self, es_client, cw_client, domain_name):
        """
        
        :param es_client: elastic search boto3 client
        :param cw_client: cloudwatch logs boto3 client
        :param domain_name: elastic search domain name
        :return: 
        """
        log_group_arn = self.retrieve_loggroup_arn(cw_client, domain_name)
        es_client.update_elasticsearch_domain_config(
            DomainName=domain_name,
            LogPublishingOptions={
                'ES_APPLICATION_LOGS':
                    {
                        'CloudWatchLogsLogGroupArn': log_group_arn,
                        'Enabled': True
                    }

            }
        )

    @classmethod
    def validate_access_policy(cls, policy_details):
        """

        :param policy_details: 
        :return: 
        """
        public_policy = False
        for statement in policy_details.get("Statement", []):
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

        return public_policy


class ESDomainDetails(object):
    """
    Basic class for ElasticSearch domain details.

    """

    def __init__(self, account, name, id, arn, tags=None, is_logging=None, encrypted=None, policy=None):
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
        self._policy = json.loads(policy) if policy else {}
        self.backup_filename = pathlib.Path(f"{self.name}.json")
        self.tags = convert_tags(tags)

    @property
    def policy(self):
        """
        :return: pretty formatted string with S3 bucket policy
        """
        return jsonDumps(self._policy)

    @property
    def public(self):
        """
        :return: boolean, True - if Elasticsearch domain policy allows public access
                          False - otherwise
        """
        return ElasticSearchOperations.validate_access_policy(self._policy)

    def backup_policy_s3(self, s3_client, bucket):
        """
        Backup Elasticsearch policy json to S3.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to put backup of S3 bucket policy

        :return: S3 path (without bucket name) to saved object with elasticsearch domain policy backup
        """
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        path = (f"queue_policies/"
                f"{self.account.id}/"
                f"{self.backup_filename.stem}_{timestamp}"
                f"{self.backup_filename.suffix}")
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, self.policy)
        return path

    def restrict_policy(self):
        """
        Restrict and replace current policy on domain.

        :return: nothing

        .. note:: This keeps self._policy unchanged.
                  You need to recheck Elasticsearch domain policy to ensure that it was really restricted.
        """
        restricted_policy = S3Operations.restrict_policy(self._policy)
        try:
            ElasticSearchOperations.put_domain_policy(self.account.client("es"), self.name, restricted_policy)
        except Exception:
            logging.exception(f"Failed to put {self.name} restricted policy")
            return False

        return True

    def set_logging(self):
        """
        
        :return: 
        """
        try:
            ElasticSearchOperations.set_domain_logging(self.account.client("es"), self.account.client("logs"), self.name)
        except Exception:
            logging.exception(f"Failed to enable {self.name} logging")
            return False

        return True


class ESDomainChecker:
    """
        Basic class for checking Elasticsearch unencrypted and logging issues in account/region.
        Encapsulates discovered Elasticsearch domains.
        """

    def __init__(self, account):
        """
        :param account: `Account` instance with Elasticsearch domains to check
        """
        self.account = account
        self.domains = []

    def get_domain(self, id):
        """
        :return: `Elasticsearch Domain` by id
        """
        for domain in self.domains:
            if domain.name == id:
                return domain
        return None

    def check(self, ids=None):
        """
        Walk through Elasticsearch domains in the account/region and put them to `self.domains`.

        :param ids: list with Elasticsearch domain ids to check, if it is not supplied - all Elasticsearch domains must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        domain_details = []
        try:
            es_client = self.account.client("es")
            if ids is None:
                ids = []
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
                logging.exception(f"Failed to describe elasticsearch domains in {self.account}")
            return False

        domain_encrypted = False
        is_logging = False
        for domain_detail in domain_details:
            domain_name = domain_detail["DomainName"]
            domain_id = domain_detail["DomainId"]
            domain_arn = domain_detail["ARN"]
            encryption_at_rest = domain_detail.get("EncryptionAtRestOptions")
            node_to_node_encryption = domain_detail.get("NodeToNodeEncryptionOptions")
            if encryption_at_rest and encryption_at_rest["Enabled"]:
                domain_encrypted = True
            elif node_to_node_encryption and node_to_node_encryption["Enabled"]:
                domain_encrypted = True

            logging_details = domain_detail.get("LogPublishingOptions")

            if logging_details:
                index_logs = logging_details.get("INDEX_SLOW_LOGS")
                search_logs = logging_details.get("SEARCH_SLOW_LOGS")
                error_logs = logging_details.get("ES_APPLICATION_LOGS")
                if (index_logs and index_logs["Enable"]) \
                        or (search_logs and search_logs["Enable"]) \
                        or (error_logs and error_logs["Enable"]):
                    is_logging = True

            tags = es_client.list_tags(ARN=domain_arn)["TagList"]

            access_policy = domain_detail.get("AccessPolicies")

            domain = ESDomainDetails(self.account,
                                     name=domain_name,
                                     id=domain_id,
                                     arn=domain_arn,
                                     tags=tags,
                                     is_logging=is_logging,
                                     encrypted=domain_encrypted,
                                     policy=access_policy)
            self.domains.append(domain)
        return True