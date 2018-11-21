import boto3
import logging

from moto import mock_sqs
from library.utility import jsonDumps


def start():
    """
    Entrypoint for mocking SQS.
    :return: nothing
    """
    # start SQS mocking with moto
    mock = mock_sqs()
    mock.start()


def create_env(queues, region):
    logging.debug(f"======> creating new SQS env from {jsonDumps(queues)}")
    sqs_client = boto3.client("sqs", region_name=region)

    for queue, props in queues.items():
        sqs_client.create_queue(QueueName=queue)

        queue_url = sqs_client.get_queue_url(QueueName=queue)["QueueUrl"]
        if 'Policy' in props:
            sqs_client.set_queue_attributes(QueueUrl=queue_url,
                                            Attributes = {
                                                'Policy': props['Policy']
                                            }
                                        )

    response = sqs_client.list_queues()["QueueUrls"]
    logging.debug(f"{jsonDumps(response)}")
