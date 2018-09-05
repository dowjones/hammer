import logging


from botocore.exceptions import ClientError
from library.aws.utility import convert_tags


class EBSOperations:
    @staticmethod
    def snapshot_make_private(ec2_client, snapshot_id):
        """
        Remove public permissions on EBS snapshot

        :param ec2_client: EC2 boto3 client
        :param snapshot_id: the ID of the snapshot

        :return: nothing
        """
        ec2_client.modify_snapshot_attribute(
            Attribute="createVolumePermission",
            CreateVolumePermission={
                "Remove": [
                    {
                        "Group": "all"
                    },
                ]
            },
            GroupNames=["all"],
            OperationType="remove",
            SnapshotId=snapshot_id
        )


class EBSVolume(object):
    """
    Basic class for EBS volume.
    Encapsulates `VolumeId`/`State`/`Encrypted` and list of `Attachments`.
    """
    def __init__(self, account, source):
        """
        :param account: `Account` instance where EBS volume is present
        :param source: single `Volumes` element as AWS returns
        """
        self.source = source
        self.account = account
        self.id = source["VolumeId"]
        self.state = source["State"]
        self.encrypted = source["Encrypted"]
        attachments = source.get('Attachments', [])
        self.attachments = { attach['InstanceId']: attach['State'] for attach in attachments } if attachments else {}
        self.tags = convert_tags(source.get('Tags', []))

    @property
    def name(self):
        """ :return: EBS volume name from tags """
        return self.tags.get("Name", None) if self.tags else None

    def __str__(self):
        name = "" if self.name is None else f"Name={self.name}, "
        return f"{self.__class__.__name__}({name}Id={self.id}, Encrypted={self.encrypted}, State={self.state}, Attachments={len(self.attachments)})"


class EBSUnencryptedVolumesChecker(object):
    """
    Basic class for checking EBS volumes in account/region.
    Encapsulates discovered EBS volumes.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with EBS volumes to check
        """
        self.account = account
        self.volumes = []

    def get_volume(self, id):
        """
        :return: `EBSVolume` by id
        """
        for volume in self.volumes:
            if volume.id == id:
                return volume
        return None

    def check(self, ids=None, tags=None):
        """
        Walk through not encrypted EBS volumes in the account/region and put them to `self.volumes`.

        :param ids: list with EBS volume ids to check, if it is not supplied - all EBS volumes must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        args = {'DryRun': False}
        if ids:
            # if ids is set - check given ids regardless of encrypted status
            args['VolumeIds'] = ids
        else:
            # else get only unencrypted volumes
            args['Filters'] = [{
                'Name': 'encrypted',
                'Values': ["false"]
            }]
            if tags:
                for key, value in tags.items():
                    args['Filters'].append(
                        {'Name': f"tag:{key}", 'Values': value if isinstance(value, list) else [value]},
                    )

        try:
            volume_details = self.account.client("ec2").describe_volumes(**args)["Volumes"]
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(ec2:{err.operation_name})")
            else:
                logging.exception(f"Failed to describe volumes in {self.account}")
            return False

        for volume_detail in volume_details:
            volume = EBSVolume(self.account, volume_detail)
            self.volumes.append(volume)
        return True

class EBSSnapshot(object):
    """
    Basic class for EBS snapshot.
    Encapsulates `SnapshotId`/`VolumeId`/`Encrypted` and list of permissions.
    """
    def __init__(self, account, source, permissions):
        """
        :param account: `Account` instance where EBS snapshot is present
        :param source: single `Snapshots` element as AWS returns
        :param permissions: result of `describe_snapshot_attribute` API call for snapshot
        """
        self.source = source
        self.permissions = permissions
        self.account = account
        self.id = source["SnapshotId"]
        self.volume_id = source["VolumeId"]
        self.tags = convert_tags(source.get('Tags', []))

    def __str__(self):
        return f"{self.__class__.__name__}(Id={self.id}, VolumeId={self.volume_id}, Public={self.public})"

    @property
    def public(self):
        """
        :return: boolean, True - if snapshot has `all` group permissions for `CreateVolumePermissions`
                          False - otherwise
        """
        for permission in self.permissions["CreateVolumePermissions"]:
            if "Group" in permission and permission["Group"] == "all":
                return True
        return False

    def make_private(self):
        """
        Remove public permissions on snapshot

        :return: nothing
        """
        EBSOperations.snapshot_make_private(self.account.client("ec2"), self.id)


class EBSPublicSnapshotsChecker(object):
    """
    Basic class for checking EBS snapshots in account/region.
    Encapsulates discovered EBS snapshots.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with EBS snapshots to check
        """
        self.account = account
        self.snapshots = []

    def get_snapshot(self, id):
        """
        :return: `EBSSnapshot` by id
        """
        for snapshot in self.snapshots:
            if snapshot.id == id:
                return snapshot
        return None

    def check(self, ids=None, tags=None):
        """
        Walk through public EBS snapshots in the account/region and put them to `self.snapshots`.

        :param ids: list with EBS snapshot ids to check, if it is not supplied - all EBS snapshots must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        args = {
            'DryRun': False,
            # You can specify AWS account IDs (if you own the snapshots),
            # 'self' for snapshots for which you own or have explicit permissions,
            # or 'all' for public snapshots.
            'RestorableByUserIds': ['all'],
            # The results can include the AWS account IDs of the specified owners,
            # 'amazon' for snapshots owned by Amazon,
            # or 'self' for snapshots that you own.
            'OwnerIds': ['self']
        }
        if ids:
            # if ids is set - check given ids regardless of encrypted status
            args['SnapshotIds'] = ids
            del args['RestorableByUserIds']
        if tags:
            args['Filters'] = []
            for key, value in tags.items():
                args['Filters'].append(
                    {'Name': f"tag:{key}", 'Values': value if isinstance(value, list) else [value]},
                )

        try:
            snapshot_details = self.account.client("ec2").describe_snapshots(**args)["Snapshots"]
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(ec2:{err.operation_name})")
            else:
                logging.exception(f"Failed to describe snapshots in {self.account}")
            return False

        for snapshot_detail in snapshot_details:
            try:
                # Need to check each snapshot attributes dispite of the fact
                # that we ask AWS to return only restorable by all snapshots as:
                # * if 'ids' set - we remove RestorableByUserIds and AWS return both public and private snapshots
                # * moto does not support RestorableByUserIds and returns all snapshots
                snapshot_permissions = self.account.client("ec2").describe_snapshot_attribute(
                    Attribute="createVolumePermission",
                    SnapshotId=snapshot_detail['SnapshotId']
                )
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(ec2:{err.operation_name})")
                else:
                    logging.exception(f"Failed to describe '{snapshot_detail['SnapshotId']}' snapshot attribute "
                                      f"in {self.account}")
                return False

            snapshot = EBSSnapshot(self.account, snapshot_detail, snapshot_permissions)
            self.snapshots.append(snapshot)
        return True
