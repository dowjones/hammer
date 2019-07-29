import boto3
import logging

from moto import mock_redshift
from library.utility import jsonDumps


def start():
    """
    Entrypoint for mocking ecs.
    :return: nothing
    """
    # start ECS mocking with moto
    mock = mock_redshift()
    mock.start()


def create_env_clusters(clusters, region):
    logging.debug(f"======> creating new Redshift clusters from {jsonDumps(clusters)}")
    redshift_client = boto3.client("redshift", region_name=region)

    test_clusters = []
    clusters_list = []

    for cluster, rule in clusters.items():
        cluster_id = redshift_client.create_cluster(
            DBName=rule["DBName"],
            ClusterIdentifier=cluster,
            ClusterType=rule["ClusterType"],
            NodeType=rule["NodeType"],
            MasterUsername=rule["MasterUsername"],
            MasterUserPassword=rule["MasterUserPassword"],
            PubliclyAccessible=rule["PubliclyAccessible"],
            Encrypted=rule["Encrypted"]
        )["Cluster"]["ClusterIdentifier"]

        test_clusters.append(cluster_id)

    # remove moto precreated clusters
    redshift_clusters_list_to_check = redshift_client.describe_clusters()
    for cluster in redshift_clusters_list_to_check["Clusters"]:

        if cluster["ClusterIdentifier"] not in test_clusters:
            redshift_client.delete_cluster(
                ClusterIdentifier=cluster["ClusterIdentifier"],
                SkipFinalClusterSnapshot=True
            )
        else:
            clusters_list.append(cluster["ClusterIdentifier"])

    logging.debug(f"{jsonDumps(clusters_list)}")

    # need to return task definitions
    return test_clusters

