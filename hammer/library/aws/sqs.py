import json
import logging
import pathlib
import os


from datetime import datetime, timezone
from botocore.exceptions import ClientError
from library.utility import jsonDumps
from library.aws.s3 import S3Operations


class SQSOperations(object):
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
    Encapsulates `Tags`, dict with policy.
    """
    def __init__(self, account, url, tags, policy=None):
        """
        :param account: `Account` instance where SQS queue is present

        :param url: `URL` of sqs queue
        :param tags: tags if SQS queue (as AWS returns)
        :param policy: str (JSON document) with SQS queue policy (as AWS returns)
        """
        self.account = account
        self.url = url
        self.name = os.path.basename(self.url)
        self.tags = tags
        self._policy = json.loads(policy) if policy else {}
        self.backup_filename = pathlib.Path(f"{self.name}.json")

    def __str__(self):
        return f"{self.__class__.__name__}(Name={self.name}, Public={self.public})"

    @property
    def policy(self):
        """
        :return: pretty formatted string with SQS Queue policy
        """
        return jsonDumps(self._policy)

    @property
    def public(self):
        """
        :return: boolean, True - if policy allows public access to SQS
        """
        return S3Operations.public_policy(self._policy)

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
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, self.policy)
        return path

    def restrict_policy(self):
        """
        Restrict and replace current policy on a queue.

        :return: nothing

        .. note:: This keeps self._policy unchanged.
                  You need to recheck SQS Queue policy to ensure that it was really restricted.
        """
        restricted_policy = S3Operations.restrict_policy(self._policy)
        try:
            SQSOperations.put_queue_policy(self.account.client("sqs"), self.url, restricted_policy)
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
            queue_urls = self.account.client("sqs").list_queues().get("QueueUrls", [])
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(sqs:{err.operation_name})")
            else:
                logging.exception(f"Failed to list queues in {self.account}")
            return False

        for queue_url in queue_urls:
            if queues is not None and queue_url not in queues:
                continue

            # get queue policy
            try:
                policy = self.account.client("sqs").get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=['Policy']
                ).get("Attributes", {}).get("Policy", None)
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
                tags = self.account.client("sqs").list_queue_tags(QueueUrl=queue_url).get("Tags", {})
            except ClientError as err:
                tags = {}
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(sqs:{err.operation_name}, "
                                  f"resource='{queue_url}')")
                else:
                    logging.exception(f"Failed to get '{queue_url}' tags in {self.account}")

            sqs_queue = SQSQueue(
                account=self.account,
                url=queue_url,
                tags=tags,
                policy=policy,
            )
            self.queues.append(sqs_queue)
        return True
