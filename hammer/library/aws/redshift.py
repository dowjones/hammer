import json
import logging
import mimetypes
import pathlib

from datetime import datetime, timezone
from io import BytesIO
from copy import deepcopy
from botocore.exceptions import ClientError
from library.utility import jsonDumps
from library.utility import timeit
from library.aws.security_groups import SecurityGroup
from collections import namedtuple
from library.aws.utility import convert_tags


# structure which describes EC2 instance
RedshiftCluster_Details = namedtuple('RedshiftCluster_Details', [
    # cluster_id
    'id',
    # subnet_group_id
    'subnet_group_name'
    ])

class RedshiftClusterOperations(object):

    @classmethod
    @timeit
    def get_redshift_vpc_security_groups(cls, redshift_client, group_id):
        """ Retrieve redshift clusters meta data with security group attached

                :param redshift_client: boto3 redshift client
                :param group_id: security group id

                :return: list with redshift clusters details
                """
        # describe rds instances with security group attached
        redshift_clusters = []

        # this will include Clusters
        clusters_res = redshift_client.describe_clusters()
        for cluster in clusters_res["Clusters"]:
            active_security_groups = [sg["VpcSecurityGroupId"] for sg in cluster['VpcSecurityGroups'] if
                                      sg["Status"] == "active"]
            if group_id in active_security_groups:
                redshift_clusters.append(RedshiftCluster_Details(
                    id=cluster["ClusterIdentifier"],
                    subnet_group_name=cluster["ClusterSubnetGroupName"]
                ))

        return redshift_clusters

    @staticmethod
    def set_cluster_encryption(redshift_client, cluster_id, kms_master_key_id):
        """
        Sets the cluster encryption using Server side encryption.

        :param redshift_client: Redshift boto3 client
        :param cluster_id: Redshift cluster name which to encrypt
        :param kms_master_key_id: Redshift cluster encryption key. default value is none.

        :return: nothing
        """

        redshift_client.modify_cluster(
            ClusterIdentifier=cluster_id,
            Encrypted=True
        )

    @staticmethod
    def set_cluster_access(redshift_client, cluster_id, public_access):
        """
        Sets the cluster access as private.

        :param redshift_client: Redshift boto3 client
        :param cluster_id: Redshift cluster name which to make as private
        :param public_access: Redshift cluster public access True or False.

        :return: nothing
        """

        redshift_client.modify_cluster(
            ClusterIdentifier=cluster_id,
            PubliclyAccessible=public_access
        )

    @staticmethod
    def enable_logging(redshift_client, cluster_id, s3_bucket):
        """
        Enable cluster audit logging.

        :param redshift_client: Redshift boto3 client
        :param cluster_id: Redshift cluster name which to make as private
        :param s3_bucket: S3 bucket to store audit logs.

        :return: nothing
        """

        redshift_client.enable_logging(
            ClusterIdentifier=cluster_id,
            BucketName=s3_bucket
        )


class RedshiftCluster(object):
    """
    Basic class for Redshift Cluster.
    Encapsulates `Owner`/`Tags`.
    """
    def __init__(self, account, name, tags, is_encrypted=None, is_public=None, is_logging=None):
        """
        :param account: `Account` instance where redshift cluster is present

        :param name: `Name` of cluster id
        :param tags: tags if redshift cluster tags (as AWS returns)
        :param is_encrypted: encrypted or not.
        """
        self.account = account
        self.name =name
        self.tags = convert_tags(tags)
        self.is_encrypt = is_encrypted
        self.is_public = is_public
        self.is_logging = is_logging

    def encrypt_cluster(self, kms_key_id=None):
        """
        Encrypt bucket with SSL encryption.
        :return: nothing        
        """
        try:
            RedshiftClusterOperations.set_cluster_encryption(self.account.client("redshift"), self.name, kms_key_id)
        except Exception:
            logging.exception(f"Failed to encrypt {self.name} cluster ")
            return False

        return True

    def modify_cluster(self, public_access):
        """
        Modify cluster as private.
        :return: nothing        
        """
        try:
            RedshiftClusterOperations.set_cluster_access(self.account.client("redshift"), self.name, public_access)
        except Exception:
            logging.exception(f"Failed to modify {self.name} cluster ")
            return False

        return True

    def enable_cluster_logging(self, s3_bucket):
        """
        Enable audit logging for cluster.
        
        @:param s3_bucket: s3 bucket to store audit logs.
        :return: nothing        
        """
        try:
            RedshiftClusterOperations.enable_logging(self.account.client("redshift"), self.name, s3_bucket)
        except Exception:
            logging.exception(f"Failed to enable logging for {self.name} cluster ")
            return False

        return True


class RedshiftEncryptionChecker(object):
    """
    Basic class for checking Redshift cluster in account.
    Encapsulates discovered Redshift cluster.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with Redshift cluster to check
        """
        self.account = account
        self.clusters = []

    def get_cluster(self, name):
        """
        :return: `Redshift cluster` by name
        """
        for cluster in self.clusters:
            if cluster.name == name:
                return cluster
        return None

    def check(self, clusters=None):
        """
        Walk through Redshift clusters in the account and check them (encrypted or not).
        Put all gathered clusters to `self.clusters`.

        :param clusters: list with Redshift cluster names to check, if it is not supplied - all clusters must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering dirung list, so get all clusters for account
            response = self.account.client("redshift").describe_clusters()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(redshift:{err.operation_name})")
            else:
                logging.exception(f"Failed to list cluster in {self.account}")
            return False

        if "Clusters" in response:
            for cluster_details in response["Clusters"]:
                tags = {}
                cluster_id = cluster_details["ClusterIdentifier"]

                if clusters is not None and cluster_id not in clusters:
                    continue

                is_encrypted = cluster_details["Encrypted"]
                if "Tags" in cluster_details:
                    tags = cluster_details["Tags"]

                cluster = RedshiftCluster(account=self.account,
                                          name=cluster_id,
                                          tags=tags,
                                          is_encrypted=is_encrypted)
                self.clusters.append(cluster)
        return True


class RedshiftClusterPublicAccessChecker(object):

    """
    Basic class for checking redshift clusters public access in account/region.
    Encapsulates check settings and discovered clusters.
    """
    def __init__(self, account):
        """
        :param account: `Account` clusters to check
        
        """
        self.account = account
        self.clusters = []

    def get_cluster(self, name):
        """
        :return: `Redshift cluster` by name
        """
        for cluster in self.clusters:
            if cluster.name == name:
                return cluster
        return None


    def check(self, clusters=None):
        """
        Walk through clusters in the account/region and check them.
        Put all gathered clusters to `self.clusters`.

        :param clusters: list with clusters to check, if it is not supplied - all clusters must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering dirung list, so get all clusters for account
            response = self.account.client("redshift").describe_clusters()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(redshift:{err.operation_name})")
            else:
                logging.exception(f"Failed to list cluster in {self.account}")
            return False

        if "Clusters" in response:
            for cluster_details in response["Clusters"]:
                tags = {}
                cluster_id = cluster_details["ClusterIdentifier"]

                if clusters is not None and cluster_id not in clusters:
                    continue

                is_public = cluster_details["PubliclyAccessible"]
                if "Tags" in cluster_details:
                    tags = cluster_details["Tags"]

                cluster = RedshiftCluster(account=self.account,
                                          name=cluster_id,
                                          tags=tags,
                                          is_public=is_public)
                self.clusters.append(cluster)

        return True


class RedshiftLoggingChecker(object):
    """
    Basic class for checking redshift cluster's logging enabled or not in account/region.
    Encapsulates check settings and discovered clusters.
    """

    def __init__(self, account):
        """
        :param account: `Account` clusters to check

        """
        self.account = account
        self.clusters = []

    def get_cluster(self, name):
        """
        :return: `Redshift cluster` by name
        """
        for cluster in self.clusters:
            if cluster.name == name:
                return cluster
        return None

    def check(self, clusters=None):
        """
        Walk through clusters in the account/region and check them.
        Put all gathered clusters to `self.clusters`.

        :param clusters: list with clusters to check, if it is not supplied - all clusters must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering dirung list, so get all clusters for account
            response = self.account.client("redshift").describe_clusters()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(redshift:{err.operation_name})")
            else:
                logging.exception(f"Failed to list cluster in {self.account}")
            return False

        if "Clusters" in response:
            for cluster_details in response["Clusters"]:
                logging_enabled = True
                tags = {}
                cluster_id = cluster_details["ClusterIdentifier"]

                if clusters is not None and cluster_id not in clusters:
                    continue

                logging_details = self.account.client("redshift").describe_logging_status(ClusterIdentifier=cluster_id)
                if "LoggingEnabled" in logging_details:
                    logging_enabled = logging_details["LoggingEnabled"]

                if "Tags" in cluster_details:
                    tags = cluster_details["Tags"]

                cluster = RedshiftCluster(account=self.account,
                                          name=cluster_id,
                                          tags=tags,
                                          is_logging=logging_enabled)
                self.clusters.append(cluster)

        return True