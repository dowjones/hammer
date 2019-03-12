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
