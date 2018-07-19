import boto3
import logging

from moto import mock_rds
from library.utility import jsonDumps
from library.aws.rds import RdsSnapshotOperations


def start():
    """
    Entrypoint for mocking EC2.
    :return: nothing
    """
    # start rds mocking with moto
    mock = mock_rds()
    mock.start()


def create_env_rds_snapshots(rds_instance_details, rds_snapshot_details, rds_cluster_instances, rds_cluster_snapshots, region):
    rds_client = boto3.client("rds", region_name=region)

    for rds_instance, rule in rds_instance_details.items():
        rds_instance_id = rds_client.create_db_instance(
            DBInstanceIdentifier=rule["DBInstanceIdentifier"],
            AllocatedStorage=rule["AllocatedStorage"],
            DBInstanceClass=rule["DBInstanceClass"],
            Engine=rule["Engine"],

        )["DBInstance"]["DBInstanceIdentifier"]

        for snapshot, rule in rds_snapshot_details.items():
            rds_snapshot_id = rds_client.create_db_snapshot(
                DBInstanceIdentifier=rds_instance_id,
                DBSnapshotIdentifier=rule["DBSnapshotIdentifier"],


            )["DBSnapshots"]["DBSnapshotIdentifier"]

            if rule["IsPublicSnapshot"]:
                RdsSnapshotOperations.make_public(rds_client, rule["Engine"], rds_snapshot_id)

    for rds_cluster_instance, rule in rds_cluster_instances.items():
        rds_cluster_instance_id = rds_client.create_db_instance(
            DBInstanceIdentifier=rule["DBInstanceIdentifier"],
            AllocatedStorage=rule["AllocatedStorage"],
            DBInstanceClass=rule["DBInstanceClass"],
            Engine=rule["Engine"],

        )["DBCluster"]["DBClusterIdentifier"]

        for snapshot, rule in rds_cluster_snapshots.items():
            rds_cluster_snapshot_id = rds_client.create_db_snapshot(
                DBInstanceIdentifier=rds_cluster_instance_id,
                DBClusterSnapshotIdentifier=rule["DBClusterSnapshotIdentifier"],


            )["DBClusterSnapshots"]["DBClusterSnapshotIdentifier"]

            if rule["IsPublicSnapshot"]:
                RdsSnapshotOperations.make_public(rds_client, rule["Engine"], rds_cluster_snapshot_id)


    rds_snapshot_details = rds_client.describe_db_snapshots(DryRun=False)["DBSnapshots"]
    logging.debug(f"{jsonDumps(rds_snapshot_details)}")



