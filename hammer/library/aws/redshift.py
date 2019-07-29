import logging

from botocore.exceptions import ClientError
from library.utility import timeit
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
    def make_private(redshift_client, cluster_id):
        """
        Sets the cluster access as private.

        :param redshift_client: Redshift boto3 client
        :param cluster_id: Redshift cluster name which to make as private.

        :return: nothing
        """

        redshift_client.modify_cluster(
            ClusterIdentifier=cluster_id,
            PubliclyAccessible=False
        )

    @staticmethod
    def cluster_encryption(redshift_client, cluster_id):
        """
        :param redshift_client: redshift client
        :param cluster_id: cluster id which need to be encrypted. 

        :return: 
        """
        # Modify cluster as encrypted.
        redshift_client.modify_cluster(
            ClusterIdentifier=cluster_id,
            Encrypted=True
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
        self.name = name
        self.tags = convert_tags(tags)
        self.is_encrypt = is_encrypted
        self.is_public = is_public
        self.is_logging = is_logging

    def make_private(self):
        """
        Modify cluster as private.
        :return: nothing        
        """
        try:
            RedshiftClusterOperations.make_private(self.account.client("redshift"), self.name)
        except Exception:
            logging.exception(f"Failed to modify {self.name} cluster ")
            return False

        return True

    def encrypt_cluster(self):
        """
                Modify cluster as encrypted.
                :return: nothing        
                """
        try:
            RedshiftClusterOperations.cluster_encryption(self.account.client("redshift"), self.name)
        except Exception:
            logging.exception(f"Failed to modify {self.name} cluster encryption ")
            return False

        return True


class RedshiftClusterChecker(object):
    """
    Basic class for checking redshift clusters public access and encryption in account/region.
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
                logging_enabled = False
                tags = {}
                cluster_id = cluster_details["ClusterIdentifier"]

                if clusters is not None and cluster_id not in clusters:
                    continue

                is_public = cluster_details["PubliclyAccessible"]
                is_encrypted = cluster_details["Encrypted"]
                if "Tags" in cluster_details:
                    tags = cluster_details["Tags"]
                try:
                    logging_details = self.account.client("redshift").describe_logging_status(
                        ClusterIdentifier=cluster_id)
                    if "LoggingEnabled" in logging_details:
                        logging_enabled = logging_details["LoggingEnabled"]
                except ClientError as err:
                    if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                        logging.error(f"Access denied in {self.account} "
                                      f"(redshift:{err.operation_name})")
                    else:
                        logging.exception(f"Failed to describe logging status cluster in {self.account}")

                cluster = RedshiftCluster(account=self.account,
                                          name=cluster_id,
                                          tags=tags,
                                          is_encrypted=is_encrypted,
                                          is_public=is_public,
                                          is_logging=logging_enabled)
                self.clusters.append(cluster)

        return True
