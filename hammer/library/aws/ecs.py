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
                ec2_instance = ec2_client.describe_instances(InstanceIds=[ec2_instance_id])['Reservations'][0]["Instances"][0]

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
    def __init__(self, account, name, arn, tags, is_logging=None):
        """
        :param account: `Account` instance where ECS task definition is present
        
        :param name: name of the task definition
        :param arn: arn of the task definition
        :param arn: tags of task definition.
        :param is_logging: logging enabled or not.
        """
        self.account = account
        self.name = name
        self.arn = arn
        self.tags = convert_tags(tags)
        self.is_logging = is_logging


class ECSLoggingChecker(object):
    """
    Basic class for checking ecs task definition's logging enabled or not in account/region.
    Encapsulates check settings and discovered task definitions.
    """

    def __init__(self, account):
        """
        :param account: `Account` task definitions to check

        """
        self.account = account
        self.task_definitions = []

    def task_definition_arns(self, name):
        """
        :return: `ECS task definition' by arn
        """
        for task_definition in self.task_definitions:
            if task_definition.name == name:
                return task_definition
        return None

    def check(self, task_definitions=None):
        """
        Walk through clusters in the account/region and check them.
        Put all gathered clusters to `self.clusters`.

        :param task_definitions: list with task definitions to check, if it is not supplied - all taks definitions must be checked

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
            tags = {}
            for task_definition_name in response["families"]:
                if task_definitions is not None and task_definition_name not in task_definitions:
                    continue

                logging_enabled = False
                task_definition = self.account.client("ecs").describe_task_definition(
                    taskDefinition=task_definition_name
                )['taskDefinition']
                task_definition_arn = task_definition["taskDefinitionArn"]
                if "containerDefinitions" in task_definition:
                    for container_definition in task_definition['containerDefinitions']:
                        if container_definition.get('logConfiguration') is None:
                            logging_enabled = False
                        else:
                            logging_enabled = True
                            break
                if "Tags" in task_definition:
                    tags = task_definition["Tags"]
                task_definition_details = ECSTaskDefinitions(account=self.account,
                                                             name=task_definition_name,
                                                             arn=task_definition_arn,
                                                             tags=tags,
                                                             is_logging=logging_enabled)
                self.task_definitions.append(task_definition_details)

        return True