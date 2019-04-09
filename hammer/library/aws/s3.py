import json
import logging
import mimetypes
import pathlib


from datetime import datetime, timezone
from io import BytesIO
from copy import deepcopy
from botocore.exceptions import ClientError
from library.utility import jsonDumps
from library.aws.utility import convert_tags


class S3Operations(object):
    @staticmethod
    def get_public_acls(acl):
        """
        Walk through S3 bucket ACL and collect those lines which allows access to `all` or `authenticated` AWS predefined groups.

        :param acl: dict with S3 bucket ACL (as AWS returns)

        :return: dict with public ACL permissions:
                    key - Amazon S3 Predefined Groups (last part of URL),
                    value - list with permissions that Amazon S3 supports in an ACL.
        """
        public_acls = {}
        for grant in acl:
            if grant["Grantee"]["Type"] == "Group":
                # use only last part of URL as a key:
                #   http://acs.amazonaws.com/groups/global/AuthenticatedUsers
                #   http://acs.amazonaws.com/groups/global/AllUsers
                who = grant["Grantee"]["URI"].split("/")[-1]
                if who == "AllUsers" or \
                   who == "AuthenticatedUsers":
                    perm = grant["Permission"]
                    # group all permissions (READ(_ACP), WRITE(_ACP), FULL_CONTROL) by AWS predefined groups
                    public_acls.setdefault(who, []).append(perm)
        return public_acls

    @classmethod
    def public_acl(cls, acl):
        """
        Check supplied S3 bucket ACL for public entries.

        :param acl: dict with S3 bucket ACL (as AWS returns)

        :return: boolean, True - if supplied dict with S3 bucket ACL has public records
                          False - otherwise
        """
        return bool(cls.get_public_acls(acl))

    @classmethod
    def public_policy(cls, policy):
        """
        Check if S3 supplied bucket policy allows public access by checking S3 bucket policy statements

        :param policy: dict with S3 bucket policy (as AWS returns)

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
        Check if S3 supplied bucket policy statement allows public access.

        :param statement: dict with S3 bucket policy statement (as AWS returns)

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
    def restrict_policy(cls, policy):
        """
        Walk through S3 bucket policy and restrict all public statements.
        It does not restrict supplied policy dict, but creates an copy and works with that copy.

        :param policy: dict with S3 bucket policy (as AWS returns)

        :return: new dict with S3 bucket policy based on old one, but with restricted public statements
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
        Restricts provided S3 bucket policy statement with RFC1918 condition.
        It performs in-place restriction of supplied statement.

        :param statement: dict with S3 bucket policy statement to restrict (as AWS returns)

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
        Check if object exists on S3 by given path.

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
    def put_bucket_policy(s3_client, bucket, policy):
        """
        Replaces a policy on a bucket. If the bucket already has a policy, the one in this request completely replaces it.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to update policy on
        :param policy: `dict` or `str` with policy. `Dict` will be transformed to string using pretty json.dumps().

        :return: nothing
        """
        policy_json = jsonDumps(policy) if isinstance(policy, dict) else policy
        s3_client.put_bucket_policy(
            Bucket=bucket,
            Policy=policy_json
        )

    @staticmethod
    def put_bucket_acl(s3_client, bucket, acl):
        """
        Sets the permissions on a bucket using canned ACL.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to set ACL on
        :param acl: canned ACL type - 'private'|'public-read'|'public-read-write'|'authenticated-read'.

        :return: nothing
        """
        s3_client.put_bucket_acl(
            Bucket=bucket,
            ACL=acl
        )

    @staticmethod
    def set_bucket_encryption(s3_client, bucket, kms_master_key_id=None):
        """
        Sets the bucket encryption using Server side encryption.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name which to encrypt
        :param kms_master_key_id: S3 bucket encryption key. default value is none.

        :return: nothing
        """
        if kms_master_key_id:
           rules = [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': kms_master_key_id
                    }
                },
            ]
        else:
            rules = [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                },
            ]

        args = {
            "Bucket": bucket,
            "ServerSideEncryptionConfiguration": {
                "Rules": rules
            },
        }
        s3_client.put_bucket_encryption(**args)


class S3Bucket(object):
    """
    Basic class for S3 bucket.
    Encapsulates `BucketName`/`Owner`/`Tags`, list of ACLs and dict with policy.
    """
    def __init__(self, account, bucket_name, owner, tags, encrypted=None, policy=None, acl=None):
        """
        :param account: `Account` instance where S3 bucket is present

        :param bucket_name: `Name` of S3 bucket
        :param owner: ['Owner']['DisplayName'] of S3 bucket (if present)
        :param tags: tags if S3 bucket (as AWS returns)
        :param encrypted: flag to identify bucket encrypted or not
        :param policy: str (JSON document) with S3 bucket policy (as AWS returns)
        :param acl: dict with S3 bucket ACL (as AWS returns)
        """
        self.account = account
        self.name = bucket_name
        self.owner = owner
        self.tags = convert_tags(tags)
        self._policy = json.loads(policy) if policy else {}
        self._acl = acl if acl else []
        self.backup_filename = pathlib.Path(f"{self.name}.json")
        self.encrypted = encrypted

    def __str__(self):
        return f"{self.__class__.__name__}(Name={self.name}, Owner={self.owner}, Public={self.public})"

    @property
    def policy(self):
        """
        :return: pretty formatted string with S3 bucket policy
        """
        return jsonDumps(self._policy)

    @property
    def acl(self):
        """
        :return: pretty formatted string with S3 bucket ACL
        """
        return jsonDumps(self._acl)

    @property
    def public_by_policy(self):
        """
        :return: boolean, True - if S3 bucket policy allows public access
                          False - otherwise
        """
        return S3Operations.public_policy(self._policy)

    @property
    def public_by_acl(self):
        """
        :return: boolean, True - if S3 bucket ACL allows public access
                          False - otherwise
        """
        return S3Operations.public_acl(self._acl)

    def get_public_acls(self):
        """
        :return: dict with public ACL permissions
        """
        return S3Operations.get_public_acls(self._acl)

    @property
    def public(self):
        """
        :return: boolean, True - if either policy or ACL allows public access to S3 bucket
        """
        return self.public_by_policy or self.public_by_acl

    def backup_policy_s3(self, s3_client, bucket):
        """
        Backup S3 bucket policy json to S3.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to put backup of S3 bucket policy

        :return: S3 path (without bucket name) to saved object with S3 bucket policy backup
        """
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        path = (f"bucket_policies/"
                f"{self.account.id}/"
                f"{self.backup_filename.stem}_{timestamp}"
                f"{self.backup_filename.suffix}")
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, self.policy)
        return path

    def restrict_policy(self):
        """
        Restrict and replace current policy on a bucket.

        :return: nothing

        .. note:: This keeps self._policy unchanged.
                  You need to recheck S3 bucket policy to ensure that it was really restricted.
        """
        restricted_policy = S3Operations.restrict_policy(self._policy)
        try:
            S3Operations.put_bucket_policy(self.account.client("s3"), self.name, restricted_policy)
        except Exception:
            logging.exception(f"Failed to put {self.name} bucket restricted policy")
            return False

        return True

    def backup_acl_s3(self, s3_client, bucket):
        """
        Backup S3 bucket ACL json to S3.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to put backup of S3 bucket ACL

        :return: S3 path (without bucket name) to saved object with S3 bucket ACL backup
        """
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        path = (f"bucket_acls/"
                f"{self.account.id}/"
                f"{self.backup_filename.stem}_{timestamp}"
                f"{self.backup_filename.suffix}")
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, self.acl)
        return path

    def restrict_acl(self):
        """
        Restrict and replace current ACL on a bucket.

        :return: nothing

        .. note:: This keeps self._acl unchanged.
                  You need to recheck S3 bucket ACL to ensure that it was really restricted.
        """
        try:
            S3Operations.put_bucket_acl(self.account.client("s3"), self.name, 'private')
        except Exception:
            logging.exception(f"Failed to put {self.name} bucket 'private' acl")
            return False

        return True

    def encrypt_bucket(self, kms_key_id=None):
        """
        Encrypt bucket with SSL encryption.
        :return: nothing
        """
        try:
            S3Operations.set_bucket_encryption(self.account.client("s3"), self.name, kms_key_id)
        except Exception:
            logging.exception(f"Failed to encrypt {self.name} bucket")
            return False

        return True

    def contains_tags(self, tags):
        for tag_name in tags:
            if tag_name not in self.tags:
                return False
            if self.tags[tag_name] not in tags[tag_name]:
                return False
        return True


class S3BucketsPolicyChecker(object):
    """
    Basic class for checking S3 bucket policy in account.
    Encapsulates discovered S3 buckets.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with S3 buckets to check
        """
        self.account = account
        self.buckets = []

    def get_bucket(self, name):
        """
        :return: `S3Bucket` by name
        """
        for bucket in self.buckets:
            if bucket.name == name:
                return bucket
        return None

    def check(self, buckets=None):
        """
        Walk through S3 buckets in the account and check them (public or not).
        Put all gathered buckets to `self.buckets`.

        :param buckets: list with S3 bucket names to check, if it is not supplied - all buckets must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering dirung list, so get all buckets for account
            response = self.account.client("s3").list_buckets()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(s3:{err.operation_name})")
            else:
                logging.exception(f"Failed to list buckets in {self.account}")
            return False

        # owner (if present) is set for all buckets in response
        owner = response.get('Owner', {}).get('DisplayName')
        for bucket in response["Buckets"]:
            bucket_name = bucket["Name"]
            if buckets is not None and bucket_name not in buckets:
                continue

            # get bucket policy
            try:
                policy = self.account.client("s3").get_bucket_policy(Bucket=bucket_name)["Policy"]
            except ClientError as err:
                if err.response['Error']['Code'] == "NoSuchBucketPolicy":
                    logging.debug(f"No policy attached to '{bucket_name}'")
                    policy = None
                elif err.response['Error']['Code'] == "NoSuchBucket":
                    # deletion was not fully propogated to S3 backend servers
                    # so bucket is still available in listing but actually not exists
                    continue
                elif err.response['Error']['Code'] == "AccessDenied":
                    logging.error(f"Access denied in {self.account} "
                                  f"(s3:{err.operation_name}, "
                                  f"resource='{bucket_name}')")
                    continue
                else:
                    logging.exception(f"Failed to get '{bucket_name}' policy in {self.account}")
                    continue

            # get bucket tags
            try:
                tags = self.account.client("s3").get_bucket_tagging(Bucket=bucket_name)['TagSet']
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(s3:{err.operation_name}, "
                                  f"resource='{bucket_name}')")
                    continue
                elif err.response['Error']['Code'] == "NoSuchTagSet":
                    tags = []
                else:
                    logging.exception(f"Failed to get '{bucket_name}' tags in {self.account}")
                    continue

            s3bucket = S3Bucket(account=self.account,
                                bucket_name=bucket_name,
                                owner=owner,
                                tags=tags,
                                policy=policy)
            self.buckets.append(s3bucket)
        return True

class S3BucketsAclChecker(object):
    """
    Basic class for checking S3 bucket ACL in account.
    Encapsulates discovered S3 buckets.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with S3 buckets to check
        """
        self.account = account
        self.buckets = []

    def get_bucket(self, name):
        """
        :return: `S3Bucket` by name
        """
        for bucket in self.buckets:
            if bucket.name == name:
                return bucket
        return None

    def check(self, buckets=None):
        """
        Walk through S3 buckets in the account and check them (public or not).
        Put all gathered buckets to `self.buckets`.

        :param buckets: list with S3 bucket names to check, if it is not supplied - all buckets must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering dirung list, so get all buckets for account
            response = self.account.client("s3").list_buckets()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(s3:{err.operation_name})")
            else:
                logging.exception(f"Failed to list buckets in {self.account}")
            return False

        # owner (if present) is set for all buckets in response
        owner = response.get('Owner', {}).get('DisplayName')
        for bucket in response["Buckets"]:
            bucket_name = bucket["Name"]
            if buckets is not None and bucket_name not in buckets:
                continue

            # get bucket ACL
            try:
                acl = self.account.client("s3").get_bucket_acl(Bucket=bucket_name)['Grants']
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(s3:{err.operation_name}, "
                                  f"resource='{bucket_name}')")
                elif err.response['Error']['Code'] == "NoSuchBucket":
                    # deletion was not fully propogated to S3 backend servers
                    # so bucket is still available in listing but actually not exists
                    pass
                else:
                    logging.exception(f"Failed to get '{bucket_name}' acl in {self.account}")
                continue

            # get bucket tags
            try:
                tags = self.account.client("s3").get_bucket_tagging(Bucket=bucket_name)['TagSet']
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(s3:{err.operation_name}, "
                                  f"resource='{bucket_name}')")
                    continue
                elif err.response['Error']['Code'] == "NoSuchTagSet":
                    tags = []
                else:
                    logging.exception(f"Failed to get '{bucket_name}' tags in {self.account}")
                    continue

            s3bucket = S3Bucket(account=self.account,
                                bucket_name=bucket_name,
                                owner=owner,
                                tags=tags,
                                acl=acl)
            self.buckets.append(s3bucket)
        return True

class S3EncryptionChecker(object):
    """
    Basic class for checking S3 bucket encryption in account.
    Encapsulates discovered S3 buckets.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with S3 buckets to check
        """
        self.account = account
        self.buckets = []

    def get_bucket(self, name):
        """
        :return: `S3Bucket` by name
        """
        for bucket in self.buckets:
            if bucket.name == name:
                return bucket
        return None

    def check(self, buckets=None):
        """
        Walk through S3 buckets in the account and check them (encrypted or not).
        Put all gathered buckets to `self.buckets`.

        :param buckets: list with S3 bucket names to check, if it is not supplied - all buckets must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering dirung list, so get all buckets for account
            response = self.account.client("s3").list_buckets()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(s3:{err.operation_name})")
            else:
                logging.exception(f"Failed to list buckets in {self.account}")
            return False

        # owner (if present) is set for all buckets in response
        owner = response.get('Owner', {}).get('DisplayName')
        for bucket in response["Buckets"]:
            bucket_name = bucket["Name"]
            if buckets is not None and bucket_name not in buckets:
                continue

            # get bucket encryption status
            try:
                self.account.client("s3").get_bucket_encryption(Bucket=bucket_name)
                bucket_encrypted = True
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(s3:{err.operation_name}, "
                                  f"resource='{bucket_name}')")
                    continue
                elif err.response['Error']['Code'] == "NoSuchBucket":
                    # deletion was not fully propogated to S3 backend servers
                    # so bucket is still available in listing but actually not exists
                    continue
                elif err.response['Error']['Code'] in ["ServerSideEncryptionConfigurationNotFoundError"]:
                    bucket_encrypted = False
                else:
                    logging.exception(f"Failed to get '{bucket_name}' encryption details in {self.account}")
                    continue

            # get bucket tags
            try:
                tags = self.account.client("s3").get_bucket_tagging(Bucket=bucket_name)['TagSet']
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(s3:{err.operation_name}, "
                                  f"resource='{bucket_name}')")
                    continue
                elif err.response['Error']['Code'] == "NoSuchTagSet":
                    tags = []
                else:
                    logging.exception(f"Failed to get '{bucket_name}' tags in {self.account}")
                    continue

            s3bucket = S3Bucket(account=self.account,
                                bucket_name=bucket_name,
                                owner=owner,
                                tags=tags,
                                encrypted=bucket_encrypted)
            self.buckets.append(s3bucket)
        return True
