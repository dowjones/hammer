import logging


from botocore.exceptions import ClientError
from library.aws.utility import convert_tags
from collections import namedtuple
from library.utility import timeit

# structure which describes EC2 instance
RDSInstance = namedtuple('RDSInstance', [
    # instance ID
    'id',
    # DB engine
    'engine',
    # instance arn
    'arn',
    # status of db instance (available or not)
    'status',
    # boolean if RDS instance is public access or not
    'public'
    ])


class RDSOperations:
    @classmethod
    @timeit
    def get_rds_instance_details_of_sg_associated(cls, rds_client, group_id):
        """ Retrieve rds instances meta data with security group attached

        :param rds_client: boto3 rds client
        :param group_id: security group id

        :return: list with rds instance details
        """
        # describe rds instances with security group attached
        rds_instances = []

        # this will include both DB and Cluster instances
        rds_response = rds_client.describe_db_instances()
        for db_instance in rds_response["DBInstances"]:
            active_security_groups = [ sg["VpcSecurityGroupId"] for sg in db_instance['VpcSecurityGroups'] if sg["Status"] == "active" ]
            if group_id in active_security_groups:
                rds_instances.append(RDSInstance(
                    id=db_instance["DBInstanceIdentifier"],
                    engine=db_instance["Engine"],
                    arn=db_instance["DBInstanceArn"],
                    status=db_instance["DBInstanceStatus"],
                    public=db_instance["PubliclyAccessible"],
                ))

        return rds_instances


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
        # tags placeholder
        self._tags = {}

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


class RdsDB(object):
    """
    Parent class for RDS database (Instance or Cluster). Child classes must define methods and fields to work with Instance or Cluster instances.
    Encapsulates `DB[Cluster]InstanceIdentifier`/`DB[Cluster]InstanceArn`/`DB[Cluster]InstanceIdentifier/Engine` and attributes.
    """
    ### all these static fields must be defined by child classes
    # method which returns information about DB instances
    describe_method = None
    # field in `describe_method` response which specifies info about DB instances
    response_field = None
    # field in `response_field` which specifies DB instance identifier
    instance_id_field = None
    # field in `response_field` which specifies DB instance ARN
    instance_arn_field = None
    # field in `response_field` which specifies DB instance storage encryption
    storage_encryption_field = None

    def __init__(self, account, source):
        """
        :param account: `Account` instance where S3 bucket is present
        :param source: dict with RDS instance properties (as `describe_method` returns)
        """
        self.account = account
        # use instance ARN as id
        self.id = source.get(self.instance_arn_field, None)
        # instance name
        self.name = source.get(self.instance_id_field, None)
        self.source = source
        # must be set later by creator
        self.attributes = []
        # name of the database engine
        self.engine = source.get('Engine', None)
        # tags placeholder
        self._tags = {}

    def __str__(self):
        return f"{self.__class__.__name__}(Id={self.id}, engine={self.engine})"

    @property
    def tags(self):
        """ :return: dict with tags associated with instance """
        return self._tags

    @tags.setter
    def tags(self, value):
        """
        Set AWS tags for instance with prior converting from AWS format to simple dict

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


class RdsInstance(RdsDB):
    describe_method = "describe_db_instances"
    response_field = "DBInstances"
    instance_id_field = "DBInstanceIdentifier"
    instance_arn_field = "DBInstanceArn"
    storage_encryption_field = "StorageEncrypted"


class RdsCluster(RdsDB):
    describe_method = "describe_db_clusters"
    response_field = "DBClusters"
    instance_id_field = "DBClusterIdentifier"
    instance_arn_field = "DBClusterArn"
    storage_encryption_field = "StorageEncrypted"


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


class RdsEncryptionChecker(object):
    """
    Basic class for checking RDS instances in account/region.
    Encapsulates discovered RDS instances.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with RDS instances to check
        """
        self.account = account
        self.instances = []

    def get_instance(self, id):
        """
        :return: `RdsInstance`/`RdsCluster` by id (ARN)
        """
        for instance in self.instances:
            if instance.id == id:
                return instance
        return None

    def collect_unencrypted_rds_instances(self, account, instance_cls):
        """
        Walk through public RDS instances (DB or Cluster, depending on `instance_cls`) in the account.
        Filter instances owned by current account in current region.
        Put all gathered instances to `self.instances`.

        :param account: `Account` instance where RDS instance is present
        :param instance_cls: `RdsInstance` or `RdsCluster`

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        marker = None
        while True:
            args = {}
            if marker:
                args['Marker'] = marker
            try:
                # describe instances
                response = getattr(self.account.client("rds"), instance_cls.describe_method)(**args)
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(rds:{err.operation_name})")
                else:
                    logging.exception(f"Failed to collect rds instance in {self.account}")
                return False

            for db_instance in response[instance_cls.response_field]:
                # create RdsInstance/RdsCluster instance
                instance = instance_cls(
                    account=account,
                    source=db_instance
                )
                # filter from all un-encrypted instances only instances owned by current account in current region
                if instance.id.startswith(f"arn:aws:rds:{account.region}:{account.id}:") and (not db_instance[instance_cls.storage_encryption_field]):
                    self.instances.append(instance)

            if "Marker" in response:
                marker = response["Marker"]
            else:
                break

        # collect tags for all un-encrypted instances
        for instance in self.instances:
            try:
                instance.tags = self.account.client("rds").list_tags_for_resource(
                    ResourceName=instance.id
                )['TagList']
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(rds:{err.operation_name})")
                else:
                    logging.exception(f"Failed to describe db instnaces '{instance.id}' tags in {self.account}")
                continue
        return True

    def check(self):
        """
        Walk through public DB and Cluster RDS instances in the account.

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        instance = self.collect_unencrypted_rds_instances(
            account=self.account,
            instance_cls=RdsInstance
        )

        cluster = self.collect_unencrypted_rds_instances(
            account=self.account,
            instance_cls=RdsCluster
        )
        return instance and cluster
