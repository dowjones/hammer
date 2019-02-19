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
            Encryption=True,
            KmsKeyId=kms_master_key_id
        )

class RedshiftCluster(object):
    """
    Basic class for Redshift Cluster.
    Encapsulates `Owner`/`Tags`.
    """
    def __init__(self, account, name, tags, is_encrypted):
        """
        :param account: `Account` instance where redshift cluster is present

        :param name: `Name` of cluster id
        :param tags: tags if redshift cluster tags (as AWS returns)
        :param is_encrypted: encrypted or not.
        """
        self.account = account
        self.name =name
        self.tags = tags
        self.is_encrypt = is_encrypted

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


class RedshiftClusterChecker(object):
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
                cluster_id = cluster_details["ClusterIdentifier"]

                if clusters is not None and cluster_id not in clusters:
                    continue

                is_encrypted = cluster_details["Encrypted"]
                if "Tags" in cluster_details:
                    tags = cluster_details["Tags"]

                cluster = RedshiftCluster(account=self.account,
                                          name=cluster_id,
                                          tags=tags,
                                          is_encrypt=is_encrypted)
                self.clusters.append(cluster)
        return True


class RedshiftInsecureSGsChecker(object):

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

    def check(self, ids=None):
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
        try:
            clusters = self.account.client("redshift").describe_clusters()
            for cluster in clusters["Clusters"]:
                for security_group in cluster["ClusterSecurityGroups"]:
                    sg_name = security_group["ClusterSecurityGroupName"]
                    status = security_group["Status"]
                    sg_details = self.account.client("redshift").describe_cluster_security_groups(
                        ClusterSecurityGroupName=sg_name)



            #describe_security_groups(**args)["SecurityGroups"]
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