import boto3
import logging

from moto import mock_s3
from library.utility import jsonDumps


def start():
    """
    Entrypoint for mocking S3.
    :return: nothing
    """
    # start S3 mocking with moto
    mock = mock_s3()
    mock.start()


def create_env(buckets):
    logging.debug(f"======> creating new S3 env from {jsonDumps(buckets)}")
    s3_client = boto3.client("s3")

    for bucket, props in buckets.items():
        s3_client.create_bucket(Bucket=bucket)

        params = {
            'Bucket': bucket,
        }

        for prop in ['ACL', 'AccessControlPolicy', 'Policy']:
            if prop in props:
                params[prop] = props[prop]

        if 'ACL' in props:
            s3_client.put_bucket_acl(**params)
        elif 'Policy' in props:
            s3_client.put_bucket_policy(**params)

    response = s3_client.list_buckets()["Buckets"]
    logging.debug(f"{jsonDumps(response)}")
    # for bucket in response:
    #     bucket_name = bucket["Name"]
    #     acl = s3_client.get_bucket_acl(Bucket=bucket_name)['Grants']
    #     logging.debug(f"{bucket_name}: {jsonDumps(acl)}")