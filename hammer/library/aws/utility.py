import boto3
import decimal
from functools import lru_cache
import json
import logging
import socket
import time


import botocore.config
from botocore.exceptions import ClientError
from boto3.session import Session


class AssumeRole:
    @staticmethod
    def role_arn(account_id, role_name):
        """ Construct role ARN from account ID and role name """
        return f"arn:aws:iam::{account_id}:role/{role_name}"

    @staticmethod
    def current_account_id():
        """ Autodetection of current account ID from STS """
        return boto3.client('sts').get_caller_identity()['Account']

    @classmethod
    def get_creds(cls, account, duration=3600):
        """
        Assume role in some account and return access credentials (access/secret key and token)

        :param account: `Account` instance
        :param duration: request credentials to be valid for given amount of seconds

        :return: dict with access/secret key and token ready to use in `boto3.session.Session`

        .. note:: there can be limitation for DurationSeconds on role level - "Maximum CLI/API session duration".
                  If you specify a value for the DurationSeconds parameter that is higher than the maximum setting,
                  the operation fails.
        """
        try:
            sts_client = boto3.client('sts')
            assume_role = sts_client.assume_role(
                RoleArn=cls.role_arn(account.id, account.role_name),
                RoleSessionName=socket.gethostname(),
                DurationSeconds=duration,
            )
        except ClientError as err:
            msg = f"Failed to assume role in {account}"
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(msg + f", access denied (sts:{err.operation_name})")
            else:
                logging.exception(msg)
            return None

        return {'aws_access_key_id': assume_role["Credentials"]["AccessKeyId"],
                'aws_secret_access_key': assume_role["Credentials"]["SecretAccessKey"],
                'aws_session_token': assume_role["Credentials"]["SessionToken"]}

    @classmethod
    def get_session(cls, account=None, region=None, duration=3600):
        """ For getting boto3 session in:
         * current account - get_session(), get_session(region=region)
         * another account with assuming role - get_session(account=Account(...))

        :param account: `Account` class instance, can be None (then session for current account returns)
        :param region: for legacy reasons (get session for current account)
        :param duration: ttl for temporary (assumed) security credentials (seconds)
        :return: boto3.session.Session object
        """
        if account is None:
            account = Account(id=cls.current_account_id(),
                              name='current',
                              region=region)
        args = {}

        msg = f"Using session for {account}"
        # do not assume role for current account
        if account.id != cls.current_account_id() and account.role_name:
            creds = cls.get_creds(account, duration)
            if creds is None:
                return None
            args = {**args, **creds}
            msg += ", assumed"

        if account.region:
            args['region_name'] = account.region
            msg += ", regional"

        try:
            session = Session(**args)
        except ClientError:
            logging.exception(f"Failed to get session for {account}")
            return None

        logging.debug(msg)
        return session


@lru_cache(maxsize=128)
class Account(object):
    """
    Basic class for AWS account.
    Encapsulates ID / name / region / role name.
    Decorated with LRU cache to reuse sessions between calls.
    """
    def __init__(self,
                 id=AssumeRole.current_account_id(), name=None, region=None,
                 role_name=None):
        self.id = id
        if name is None and self.id == AssumeRole.current_account_id():
            self.name = 'current'
        else:
            self.name = name
        self.region = region
        self.role_name = role_name
        # `DurationSeconds` paramater for `assume_role`
        self.session_duration = 3600
        # timestamp when `boto3.session.Session` was obtained last time
        self.session_timestamp = 0
        # variable for caching `boto3.session.Session`
        self._session = None

    def __str__(self):
        name = f", name='{self.name}'" if self.name else ""
        region = f", region='{self.region}'" if self.region else ""
        role = f", role='{self.role_name}'" if self.role_name else ""
        return f"{self.__class__.__name__}(id='{self.id}'{name}{region}{role})"

    @property
    def session(self):
        """
        Cache/renew `boto3.session.Session` for account.

        :return: `boto3.session.Session` instance
        """

        # it seems that AWS Lambda reuse cache between lambda invocations, so
        # cached session must be validated for expiration (half of session duration period)
        if self._session is None or \
           time.time() - self.session_timestamp > self.session_duration / 2:
            self.session_timestamp = time.time()
            self._session = AssumeRole.get_session(account=self, duration=self.session_duration)
        return self._session

    def client(self, service_name, **args):
        """
        Create a low-level service client by name using session for current account

        :param service_name: name of AWS service

        :return: Service client instance
        """
        if service_name == "s3" and "config" not in args:
            # Specifying Signature Version in Request Authentication:
            # Amazon S3 supports only Signature Version 4 for below regions
            # Asia Pacific (Mumbai), Asia Pacific (Seoul), EU (Frankfurt) and China (Beijing).
            # For all other regions Amazon S3 supports both Signature Version 4 and Signature Version 2.
            args["config"] = boto3.session.Config(signature_version="s3v4")
        elif service_name == "ec2" and "config" not in args:
            args["config"] = botocore.config.Config(retries={'max_attempts': 10})
        return self.session.client(service_name, **args)

    def resource(self, service_name, **args):
        """
        Create a resource service by name using session for current account

        :param service_name: name of AWS service

        :return: Service resource instance
        """
        return self.session.resource(service_name, **args)


class Sns:
    """ Class for SNS operations """
    @staticmethod
    def publish(arn, payload):
        """
        Publish payload to sns topics by arn with payload auto detection

        :param arn: SNS topic ARN
        :param payload: payload to send to SNS (dict, str)

        :return: Response for Publish action - dict with `MessageId`
        """
        if isinstance(payload, dict):
            message = json.dumps(payload)
        elif isinstance(payload, str):
            message = payload
        else:
            raise Exception(f"Unsupported payload type {type(payload)}")

        logging.debug(f"Notifying {arn}")
        client = boto3.client('sns')
        client.publish(
            TopicArn=arn,
            Message=message,
        )


class DDB:
    @staticmethod
    def track_progress(table, request_id):
        table.update_item(
            Key={
                'request_id': request_id
            },
            UpdateExpression='SET updated=:upd, progress=progress + :val',
            ExpressionAttributeValues={':upd': int(time.time()), ':val': 1})

    @staticmethod
    def _convert_item(item):
        for k in item.keys():
            if isinstance(item[k], decimal.Decimal):
                item[k] = int(item[k])
        return item

    @staticmethod
    def get_request_data(table, request_id):
        item = table.get_item(Key={'request_id': request_id})
        if 'Item' in item:
            return DDB._convert_item(item['Item'])

    @staticmethod
    def add_request(table, request_id, request_params, total):
        table.put_item(Item={
            'request_id': request_id,
            'request_params': request_params,
            'progress': 0,
            'total': total,
            'updated': int(time.time())
        })


class AWSMetric(object):
    """
    Encapsulates AWS CloudWatch metric
    """
    def __init__(self, name, value, unit):
        self.name = name
        self.value = value
        self.unit = unit

    def __str__(self):
        return f"{self.__class__.__name__}(Name={self.name}, Value='{self.value} {self.unit}')"


class AWSMetricUnits(object):
    """
    Describes possible AWS metrics units
    """
    count   = 'Count'
    seconds = 'Seconds'
    bytes   = 'Bytes'
    bps     = 'Bytes/Second'
    mb      = 'Megabytes'


class CloudWatch:
    @staticmethod
    def put_metrics(namespace, dimensions, metrics):
        """
        General method to put CloudWatch metrics by namespace and dimensions.

        :param namespace: `Namespace` to put metric to
        :param dimensions: `Dimensions` to associate with metric (list of {`Name`: ... : `Value`: ...})
        :param metrics: list of `AWSMetric` instances, or single `AWSMetric` instance

        :return: nothing
        """
        if not isinstance(metrics, list):
            metrics = [metrics]
        client = boto3.client('cloudwatch')
        try:
            client.put_metric_data(Namespace=namespace,
                                   MetricData=[
                                       {'MetricName': metric.name,
                                        'Dimensions': dimensions,
                                        'Value': metric.value,
                                        'Unit': metric.unit}
                                       for metric in metrics
                                   ])
        except Exception as err:
            logging.warning(f"failed to put metrics\n{err}")

    @classmethod
    def put_lambda_metrics(cls, func_name, metrics):
        """
        Put CloudWatch metric to standart AWS Lambda namespace with `function name` dimension associated.

        :param func_name: Lambda function name to associate
        :param metrics: list of `AWSMetric` instances, or single `AWSMetric` instance

        :return: nothing
        """
        logging.debug(f"Putting '{func_name}' metrics: {metrics}")
        cls.put_metrics(
            namespace="AWS/Lambda",
            dimensions=[{
                'Name': 'FunctionName',
                'Value': func_name,
            }],
            metrics=metrics
        )


def convert_tags(tags):
    """
    Convert tags from AWS format [{'Key': '...', 'Value': '...'}, ...] to {'Key': 'Value', ...} format

    :param tags: tags in native AWS format

    :return: dict with tags ready to store in DynamoDB
    """
    # dynamodb does not like empty strings
    # but Value can be empty, so convert it to None
    empty_converter = lambda x: x if x != "" else None
    return {tag['Key']: empty_converter(tag['Value']) for tag in tags} if tags else {}
