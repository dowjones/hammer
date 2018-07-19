import boto3
import logging

from moto import mock_ec2
from library.utility import jsonDumps


def start():
    """
    Entrypoint for mocking EC2.
    :return: nothing
    """
    # start EC2 mocking with moto
    mock = mock_ec2()
    mock.start()


def create_env_volumes(volumes, region):
    logging.debug(f"======> creating new EC2 env from {jsonDumps(volumes)}")
    ec2_client = boto3.client("ec2", region_name=region)

    for volume, rule in volumes.items():
        volume_id = ec2_client.create_volume(
                Size=123,
                AvailabilityZone=rule["AvailabilityZone"],
                Encrypted=rule["Encrypted"]
        )['VolumeId']

        volumes[volume]["Id"] = volume_id

    # IDs of created volumes
    test_volumes = [ prop["Id"] for prop in volumes.values() ]

    # remove moto precreated volumes
    volumes_to_check = ec2_client.describe_volumes(DryRun=False)["Volumes"]
    for volume in volumes_to_check:
        if volume["VolumeId"] not in test_volumes:
            ec2_client.delete_volume(VolumeId=volume["VolumeId"],
                                     DryRun=False)

    volumes = ec2_client.describe_volumes(DryRun=False)["Volumes"]
    logging.debug(f"{jsonDumps(volumes)}")

    # need to return volumes as checker returns only unencrypted volumes
    # as a result missing encrypted in test results
    return test_volumes

def create_env_snapshots(volumes, snapshots, region):
    logging.debug(f"======> extending EC2 env from {jsonDumps(snapshots)}")
    ec2_client = boto3.client("ec2", region_name=region)

    for snapshot, rule in snapshots.items():
        volume_name = rule["Volume"]
        volume_id = volumes[volume_name]["Id"]

        snapshot_id = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=rule["Description"]

        )['SnapshotId']
        snapshots[snapshot]["Id"] = snapshot_id

        if rule["IsPublicSnapshot"]:
            ec2_client.modify_snapshot_attribute(
                Attribute="createVolumePermission",
                GroupNames= [ "all" ],
                OperationType="add",
                SnapshotId=snapshot_id
            )

    # IDs of created snapshots
    test_snapshots = [ prop["Id"] for prop in snapshots.values() ]

    # remove moto precreated snapshots
    snapshots_to_check = ec2_client.describe_snapshots(DryRun=False)["Snapshots"]
    for snapshot in snapshots_to_check:
        if snapshot["SnapshotId"] not in test_snapshots:
            ec2_client.delete_snapshot(SnapshotId=snapshot["SnapshotId"],
                                     DryRun=False)

    snapshots = ec2_client.describe_snapshots(DryRun=False)["Snapshots"]
    logging.debug(f"{jsonDumps(snapshots)}")