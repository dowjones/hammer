import logging


from botocore.exceptions import ClientError
from library.aws.utility import convert_tags


class RdsSnapshotOperations(object):
    @staticmethod
    def make_private(rds_client, engine, snapshot_id):
        """
        Change RDS snapshot to be private.

        :param rds_client: RDS boto3 client
        :param engine: The name of the database engine to modify snapshot attribute for (aurora, aurora-*, mariadb, mysql, ...)
        :param snapshot_id: The identifier for the DB snapshot to make private

        :return: nothing
        """
        snapshot = RdsClusterSnapshot if engine.startswith("aurora") else RdsInstanceSnapshot
        args = {
            snapshot.snapshot_id_field: snapshot_id,
            'AttributeName': 'restore',
            'ValuesToRemove': [ 'all' ]
        }
        # TODO: error handling
        getattr(rds_client, snapshot.modify_attribute_method)(
            **args
        )

    @staticmethod
    def make_public(rds_client, engine, snapshot_id):
        """
        Change RDS snapshot to be public.

        :param rds_client: RDS boto3 client
        :param engine: The name of the database engine to modify snapshot attribute for (aurora, aurora-*, mariadb, mysql, ...)
        :param snapshot_id: The identifier for the DB snapshot to make private

        :return: nothing
        """
        snapshot = RdsClusterSnapshot if engine.startswith("aurora") else RdsInstanceSnapshot
        args = {
            snapshot.snapshot_id_field: snapshot_id,
            'AttributeName': 'restore',
            'ValuesToAdd': [ 'all' ]
        }
        # TODO: error handling
        getattr(rds_client, snapshot.modify_attribute_method)(
            **args
        )


class RdsSnapshot(object):
    """
    Parent class for RDS snapshot (DB or Cluster). Child classes must define methods and fields to work with DB or Cluster instances.
    Encapsulates `DB[Cluster]SnapshotIdentifier`/`DB[Cluster]SnapshotArn`/`DB[Cluster]InstanceIdentifier/Engine` and attributes.
    """
    ### all these static fields must be defined by child classes
    # method which returns information about DB snapshots
    describe_method = None
    # field in `describe_method` response which specifies info about DB snapshots
    response_field = None
    # field in `response_field` which specifies DB snapshot identifier
    snapshot_id_field = None
    # field in `response_field` which specifies DB snapshot ARN
    snapshot_arn_field = None
    # field in `response_field` which specifies DB instance identifier
    db_id_field = None
    # method to use for modifying snaphost attributes
    modify_attribute_method = None

    def __init__(self, account, source):
        """
        :param account: `Account` instance where S3 bucket is present
        :param source: dict with RDS snapshot properties (as `describe_method` returns)
        """
        self.account = account
        # use snapshot ARN as id
        self.id = source.get(self.snapshot_arn_field, None)
        # DB instance identifier of the DB instance this DB snapshot was created from
        self.db = source.get(self.db_id_field, None)
        # snapshot name
        self.name = source.get(self.snapshot_id_field, None)
        self.source = source
        # must be set later by creator
        self.attributes = []
        # name of the database engine
        self.engine = source.get('Engine', None)

    def __str__(self):
        return f"{self.__class__.__name__}(Id={self.id}, db={self.db}, " \
               f"engine={self.engine})"

    @property
    def tags(self):
        """ :return: dict with tags associated with snapshot """
        return self._tags

    @tags.setter
    def tags(self, value):
        """
        Set AWS tags for snapshot with prior converting from AWS format to simple dict

        :param value: AWS tags as AWS returns
        """
        self._tags = convert_tags(value)


class RdsInstanceSnapshot(RdsSnapshot):
    describe_method = "describe_db_snapshots"
    response_field = "DBSnapshots"
    snapshot_id_field = "DBSnapshotIdentifier"
    snapshot_arn_field = "DBSnapshotArn"
    db_id_field = "DBInstanceIdentifier"
    modify_attribute_method = "modify_db_snapshot_attribute"


class RdsClusterSnapshot(RdsSnapshot):
    describe_method = "describe_db_cluster_snapshots"
    response_field = "DBClusterSnapshots"
    snapshot_id_field = "DBClusterSnapshotIdentifier"
    snapshot_arn_field = "DBClusterSnapshotArn"
    db_id_field = "DBClusterIdentifier"
    modify_attribute_method = "modify_db_cluster_snapshot_attribute"


class RdsSnapshotsChecker(object):
    """
    Basic class for checking RDS snapshots in account/region.
    Encapsulates discovered RDS snapshots.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with RDS snapshots to check
        """
        self.account = account
        self.snapshots = []

    def get_snapshot(self, id=None, name=None):
        """
        :return: `RdsInstanceSnapshot`/`RdsClusterSnapshot` by id (ARN) or name
        """
        for snapshot in self.snapshots:
            if id is not None and snapshot.id == id:
                return snapshot
            elif name is not None and snapshot.name == name:
                return snapshot
        return None

    def collect_public_rds_snapshots(self, account, snapshot_cls):
        """
        Walk through public RDS snapshots (DB or Cluster, depending on `snapshot_cls`) in the account.
        Filter snapshots owned by current account in current region.
        Put all gathered snapshots to `self.snapshots`.

        :param account: `Account` instance where RDS snapshot is present
        :param snapshot_cls: `RdsInstanceSnapshot` or `RdsClusterSnapshot`

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        marker = None
        while True:
            # ask AWS to return only public snapshots
            args = {
                'SnapshotType': 'public',
                'IncludePublic': True
            }
            if marker:
                args['Marker'] = marker
            try:
                # describe public snapshots
                response = getattr(self.account.client("rds"), snapshot_cls.describe_method)(**args)
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(rds:{err.operation_name})")
                else:
                    logging.exception(f"Failed to collect rds snapshots in {self.account}")
                return False

            for db_snapshot in response[snapshot_cls.response_field]:
                # create RdsInstanceSnapshot/RdsClusterSnapshot instance
                snapshot = snapshot_cls(
                    account=account,
                    source=db_snapshot
                )
                # filter from all public snapshots only snapshots owned by current account in current region
                if snapshot.id.startswith(f"arn:aws:rds:{account.region}:{account.id}:"):
                    self.snapshots.append(snapshot)

            if "Marker" in response:
                marker = response["Marker"]
            else:
                break

        # collect tags for all public snapshots
        for snapshot in self.snapshots:
            try:
                snapshot.tags = self.account.client("rds").list_tags_for_resource(
                    ResourceName=snapshot.id
                )['TagList']
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(rds:{err.operation_name})")
                else:
                    logging.exception(f"Failed to describe db snapshot '{snapshot.id}' tags in {self.account}")
                continue
        return True

    def check(self):
        """
        Walk through public DB and Cluster RDS snapshots in the account.

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        instance = self.collect_public_rds_snapshots(
            account=self.account,
            snapshot_cls=RdsInstanceSnapshot
        )

        cluster = self.collect_public_rds_snapshots(
            account=self.account,
            snapshot_cls=RdsClusterSnapshot
        )
        return instance and cluster
