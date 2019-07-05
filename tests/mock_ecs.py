import boto3
import logging

from moto import mock_ecs
from library.utility import jsonDumps


def start():
    """
    Entrypoint for mocking ecs.
    :return: nothing
    """
    # start ECS mocking with moto
    mock = mock_ecs()
    mock.start()


def create_env_task_definitions(task_definitions, region):
    logging.debug(f"======> creating new ECS task definitions from {jsonDumps(task_definitions)}")
    ecs_client = boto3.client("ecs", region_name=region)

    test_task_definitions = []

    for task_definition, rule in task_definitions.items():
        ecs_client.register_task_definition(
            family=task_definition,
            containerDefinitions=rule["containerDefinitions"]
        )

        test_task_definitions.append(task_definition)

    # remove moto precreated task definitions
    task_definitions_list_to_check = ecs_client.list_task_definition_families()
    for task_definition in task_definitions_list_to_check["families"]:
        if task_definition not in test_task_definitions:
            ecs_client.deregister_task_definition(
                taskDefinition=task_definition
            )

    task_definitions = ecs_client.list_task_definition_families()["families"]
    logging.debug(f"{jsonDumps(task_definitions)}")

    # need to return task definitions
    return test_task_definitions

