import logging

from botocore.exceptions import ClientError
from library.utility import timeit
from collections import namedtuple
from library.aws.utility import convert_tags

# structure which describes EC2 instance
ECSCluster_Details = namedtuple('ECSCluster_Details', [
    # cluster_id
    'cluster_arn',
    # subnet_group_id
    'cluster_instance_arn'
])


class ECSClusterOperations(object):
    @classmethod
    @timeit
    def get_ecs_instance_security_groups(cls, ec2_client, ecs_client, group_id):
        """ Retrieve ecs clusters meta data with security group attached

            :param ec2_client: boto3 ec2 client
            :param ecs_client: boto3 ECS client
            :param group_id: security group id

            :return: list with ecs clusters details
        """
        # describe ecs instances with security group attached
        ecs_instances = []

        # this will include Clusters
        clusters_res = ecs_client.list_clusters()
        for cluster_arn in clusters_res["clusterArns"]:
            list_container_instances = ecs_client.list_container_instances(
                cluster=cluster_arn
            )

            for instance_arn in list_container_instances["containerInstanceArns"]:
                container_instance = ecs_client.describe_container_instances(
                    cluster=cluster_arn,
                    containerInstances=[
                        instance_arn,
                    ]
                )

                ec2_instance_id = container_instance[0]["ec2InstanceId"]
                ec2_instance = \
                    ec2_client.describe_instances(InstanceIds=[ec2_instance_id])['Reservations'][0]["Instances"][0]

                if group_id in str(ec2_instance["SecurityGroups"]):
                    ecs_instances.append(ECSCluster_Details(
                        cluster_arn=cluster_arn,
                        cluster_instance_arn=instance_arn
                    ))

        return ecs_instances


class ECSTaskDefinitions(object):
    """
    Basic class for ECS task definitions.

    """

    def __init__(self, account, name, arn, tags, is_logging=None, disabled_logging_container_names=None,
                 is_privileged=None, privileged_container_names=None, external_image=None,
                 container_image_details=None):
        """

        :param account: `Account` instance where ECS task definition is present
        :param name: name of the task definition
        :param arn: arn of the task definition
        :param tags: tags of task definition.
        :param is_logging: boolean. Task definition's container logging is enabled or not
        :param disabled_logging_container_names: List of containers which logging disabled.
        :param is_privileged: boolean
        :param privileged_container_names: List of containers which privileged access enabled
        :param external_image: boolean 
        :param container_image_details: List of containers which image source is taken from external
        """

        self.account = account
        self.name = name
        self.arn = arn
        self.tags = convert_tags(tags)
        self.is_logging = is_logging
        self.disabled_logging_container_names = disabled_logging_container_names
        self.is_privileged = is_privileged
        self.privileged_container_names = privileged_container_names
        self.external_image = external_image
        self.container_image_details = container_image_details


class ECSChecker(object):
    """
    Basic class for checking ecs task definition's logging/privileged access/image source in account/region.
    Encapsulates check settings and discovered task definition's containers.
    """

    def __init__(self, account):
        """
        :param account: `Account` task definitions to check

        """
        self.account = account
        self.task_definitions = []

    def check(self, task_definitions=None):
        """
        Walk through clusters in the account/region and check them.
        Put all ECS task definition's container details.

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # AWS does not support filtering, so get all task definition family details for account
            response = self.account.client("ecs").list_task_definition_families()
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(ecs:{err.operation_name})")
            else:
                logging.exception(f"Failed to list task definitions in {self.account}")
            return False

        if "families" in response:
            for task_definition_name in response["families"]:
                if task_definitions is not None and task_definition_name not in task_definitions:
                    continue

                tags = {}
                container_image_details = []
                disabled_logging_container_names = []
                privileged_container_names = []
                try:
                    task_definition = self.account.client("ecs").describe_task_definition(
                        taskDefinition=task_definition_name
                    )['taskDefinition']
                    task_definition_arn = task_definition["taskDefinitionArn"]
                    if "containerDefinitions" in task_definition:
                        for container_definition in task_definition['containerDefinitions']:
                            container_name = container_definition["name"]
                            if container_definition.get('logConfiguration') is None:
                                disabled_logging_container_names.append(container_name)

                            if container_definition.get('privileged') is not None \
                                    and container_definition['privileged']:
                                privileged_container_names.append(container_name)

                            image = container_definition.get('image')
                            image_details = {}
                            if image is not None:
                                if image.split("/")[0].split(".")[-2:] != ['amazonaws', 'com']:
                                    image_details["container_name"] = container_name
                                    image_details["image_url"] = image
                                    container_image_details.append(image_details)

                        if len(disabled_logging_container_names) > 0:
                            logging_enabled = False
                        else:
                            logging_enabled = True

                        if len(privileged_container_names) > 0:
                            is_privileged = True
                        else:
                            is_privileged = False

                        if len(container_image_details) > 0:
                            external_image = True
                        else:
                            external_image = False

                        if "Tags" in task_definition:
                            tags = task_definition["Tags"]
                        task_definition_details = ECSTaskDefinitions(account=self.account,
                                                                     name=task_definition_name,
                                                                     arn=task_definition_arn,
                                                                     tags=tags,
                                                                     is_logging=logging_enabled,
                                                                     disabled_logging_container_names=disabled_logging_container_names,
                                                                     is_privileged=is_privileged,
                                                                     privileged_container_names=privileged_container_names,
                                                                     external_image=external_image,
                                                                     container_image_details=container_image_details,
                                                                     )
                        self.task_definitions.append(task_definition_details)
                except ClientError as err:
                    if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                        logging.error(f"Access denied in {self.account} "
                                      f"(ecs:{err.operation_name})")
                    else:
                        logging.exception(f"Failed to describe task definitions in {self.account} "
                                          f"for task {task_definition_name}")
                    continue

        return True