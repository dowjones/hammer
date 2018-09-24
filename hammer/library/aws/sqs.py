import json
import logging
import mimetypes
import pathlib


from datetime import datetime, timezone
from io import BytesIO
from copy import deepcopy
from botocore.exceptions import ClientError
from library.utility import jsonDumps


class SQSOperations(object):

    @classmethod
    def public_policy(cls, policy):
        """
        Check if SQS queue policy allows public access by checking policy statements

        :param policy: dict with SQS queue policy (as AWS returns)

        :return: boolean, True - if any policy statement has public access allowed
                          False - otherwise
        """
        for statement in policy.get("Statement", []):
            if cls.public_statement(statement):
                return True
        return False

    @staticmethod
    def public_statement(statement):
        """
        Check if SQS queue supplied policy statement allows public access.

        :param statement: dict with SQS queue policy statement (as AWS returns)

        :return: boolean, True - if statement allows access from '*' `Principal`, not restricted by `IpAddress` condition
                          False - otherwise
        """
        effect = statement['Effect']
        principal = statement.get('Principal', {})
        # check both `Principal` - `{"AWS": "*"}` and `"*"`
        # and condition (if exists) to be restricted (not "0.0.0.0/0")
        if effect == "Allow" and (principal == "*" or principal.get("AWS") == "*"):
            return True

        return False

    @classmethod
    def restrict_policy(cls, policy):
        """
        Walk through SQS queue policy and restrict all public statements.
        It does not restrict supplied policy dict, but creates an copy and works with that copy.

        :param policy: dict with SQS queue policy (as AWS returns)

        :return: new dict with SQS queue policy based on old one, but with restricted public statements
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
        Restricts provided SQS queue policy statement with RFC1918 condition.
        It performs in-place restriction of supplied statement.

        :param statement: dict with SQS queue policy statement to restrict (as AWS returns)

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

    @staticmethod
    def object_exists(s3_client, bucket, path):
        """
        Check if object exists on SQS queue by given path.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name
        :param path: S3 object path

        :return: True - if object exists by given `path` on given `bucket`,
                 Fasle - otherwise
        """
        try:
            s3_client.head_object(Bucket=bucket, Key=path)
            return True
        except ClientError:
            return False

    @staticmethod
    def get_object(s3_client, bucket, path):
        """
        Get content of S3 object.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name
        :param path: S3 object path

        :return: Content of requested `path` on S3 `bucket` as a bytes stream (BytesIO object)
        """
        output = BytesIO()
        s3_client.download_fileobj(bucket, path, output)
        return output.getvalue().strip()

    @staticmethod
    def put_object(s3_client, bucket, file_name, file_data):
        """
        Upload some data to private S3 object with `file_name` key.


        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to put data to
        :param file_name: S3 full path where to put data to (Key)
        :param file_data: `dict` or `str` of data to put. `Dict` will be transformed to string using pretty json.dumps().

        :return: `S3.Client.put_object` Response dict
        """
        content_type = mimetypes.guess_type(file_name)[0]
        if isinstance(file_data, dict):
            payload = jsonDumps(file_data)
        elif isinstance(file_data, str):
            payload = file_data
        elif isinstance(file_data, BytesIO):
            payload = file_data
            payload.seek(0)
        else:
            raise Exception(f"Failed to detect file_data type for {file_name}\n{file_data}")

        s3_client.put_object(
            Bucket=bucket,
            Key=file_name,
            ACL='private',
            ContentType=content_type if content_type is not None else '',
            Body=payload,
        )

    @staticmethod
    def put_queue_policy(sqs_client, queue_url, policy):
        """
        Replaces a policy on a queue. If the queue already has a policy, the one in this request completely replaces it.

        :param sqs_client: SQS boto3 client
        :param queue_url: SQS queue url where to update policy on
        :param policy: `dict` or `str` with policy. `Dict` will be transformed to string using pretty json.dumps().

        :return: nothing
        """
        policy_json = jsonDumps(policy) if isinstance(policy, dict) else policy
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                'Policy': policy_json
            }
        )


class SQSQueue(object):
    """
    Basic class for SQS queue.
    Encapsulates `Owner`/`Tags`, dict with policy.
    """
    def __init__(self, account, name, owner, tags, policy=None):
        """
        :param account: `Account` instance where SQS queue is present

        :param name: `Name` of sqs queue
        :param owner: ['Owner']['DisplayName'] of SQS queue (if present)
        :param tags: tags if SQS queue (as AWS returns)
        :param policy: str (JSON document) with SQS queue policy (as AWS returns)
        """
        self.account = account
        self.name =name
        self.owner = owner
        self.tags = tags
        self._policy = json.loads(policy) if policy else {}
        self.backup_filename = pathlib.Path(f"{self.name}.json")

    def __str__(self):
        return f"{self.__class__.__name__}(Name={self.name}, Owner={self.owner}, Public={self.public})"

    @property
    def policy(self):
        """
        :return: pretty formatted string with SQS Queue policy
        """
        return jsonDumps(self._policy)

    @property
    def public_by_policy(self):
        """
        :return: boolean, True - if SQS Queue policy allows public access
                          False - otherwise
        """
        return SQSOperations.public_policy(self._policy)

    @property
    def public(self):
        """
        :return: boolean, True - if policy allows public access to SQS
        """
        return self.public_by_policy

    def backup_policy_s3(self, s3_client, bucket):
        """
        Backup S3 bucket policy json to S3.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to put backup of S3 bucket policy

        :return: S3 path (without bucket name) to saved object with S3 bucket policy backup
        """
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        path = (f"queue_policies/"
                f"{self.account.id}/"
                f"{self.backup_filename.stem}_{timestamp}"
                f"{self.backup_filename.suffix}")
        if SQSOperations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        SQSOperations.put_object(s3_client, bucket, path, self.policy)
        return path

    def restrict_policy(self):
        """
        Restrict and replace current policy on a queue.

        :return: nothing

        .. note:: This keeps self._policy unchanged.
                  You need to recheck SQS Queue policy to ensure that it was really restricted.
        """
        restricted_policy = SQSOperations.restrict_policy(self._policy)
        try:
            SQSOperations.put_queue_policy(self.account.client("sqs"), self.name, restricted_policy)
        except Exception:
            logging.exception(f"Failed to put {self.name} restricted policy")
            return False

        return True


class SQSPolicyChecker(object):
    """
    Basic class for checking SQS queue policy in account.
    Encapsulates discovered SQS queue.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with SQS queue to check
        """
        self.account = account
        self.queues = []

    def get_queue(self, name):
        """
        :return: `SQS Queue` by name
        """
        for queue_url in self.queues:
            if queue_url.name == name:
                return queue_url
        return None

    def check(self, queues=None):
        """
        Walk through SQS queues in the account and check them (public or not).
        Put all gathered queues to `self.queues`.

        :param queues: list with SQS queue names to check, if it is not supplied - all queue must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering dirung list, so get all queues for account
            response = self.account.client("sqs").list_queues()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(sqs:{err.operation_name})")
            else:
                logging.exception(f"Failed to list queues in {self.account}")
            return False

        # owner (if present) is set for all queues in response
        owner = response.get('Owner', {}).get('DisplayName')
        if "QueueUrls" in response:
            for queue_url in response["QueueUrls"]:
                if queues is not None and queue_url not in queues:
                    continue

                # get queue policy
                try:
                    policy = ""
                    policy_response = self.account.client("sqs").get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])
                    if "Attributes" in policy_response and "Policy" in policy_response:
                        policy = policy_response["Attributes"]["Policy"]
                except ClientError as err:
                    if err.response['Error']['Code'] == "AccessDenied":
                        logging.error(f"Access denied in {self.account} "
                                      f"(sqs:{err.operation_name}, "
                                      f"resource='{queue_url}')")
                    else:
                        logging.exception(f"Failed to get '{queue_url}' policy in {self.account}")
                    return False

                # get queue tags
                try:
                    tags_response = self.account.client("sqs").list_queue_tags(QueueUrl=queue_url)
                    tags = {}
                    if "Tags" in tags_response:
                        tags = tags_response["Tags"]
                except ClientError as err:
                    if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                        logging.error(f"Access denied in {self.account} "
                                      f"(sqs:{err.operation_name}, "
                                      f"resource='{queue_url}')")
                        continue
                    else:
                        logging.exception(f"Failed to get '{queue_url}' tags in {self.account}")
                        continue
                #if policy != "":
                sqs_queue = SQSQueue(account=self.account,
                                    name=queue_url,
                                    owner=owner,
                                    tags=tags,
                                    policy=policy)
                self.queues.append(sqs_queue)
        return True
