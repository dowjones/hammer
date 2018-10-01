import logging
import requests
import botocore.config


from operator import itemgetter
from library.logger import set_logging
from library.utility import jsonDumps
from library.aws.utility import Account


# https://wiki.centos.org/Cloud/AWS
PRODUCT_CODE = "aw0evgkw8e5c1q413zgy5pjce"

def send_response(event, context, status, data=None):
    url = event['ResponseURL']

    payload = {
        'Status': status,
        'Reason': "See the details in CloudWatch Log Stream: " + context.log_stream_name,
        'PhysicalResourceId': context.log_stream_name,
        'StackId': event.get('StackId', ''),
        'RequestId': event.get('RequestId', ''),
        'LogicalResourceId': event.get('LogicalResourceId', ''),
        'Data': data
    }

    response = requests.put(
        url,
        json=payload,
        headers={'content-type': ''}
    )
    logging.info(f"response:\n{response}")


def lambda_handler(event, context):
    set_logging(level=logging.DEBUG)

    logging.debug(f"Got request\n{jsonDumps(event)}")

    if event.get('RequestType', "") == "Delete":
        send_response(event, context, "SUCCESS")
        return

    region = event.get('ResourceProperties', {}).get('Region', None)
    if region is None:
        logging.error("Failed to get region from event")
        send_response(event, context, "FAILED")

    try:
        account = Account(region=region)
        ec2 = account.client(
            'ec2',
            config=botocore.config.Config(retries={'max_attempts': 3})
        )
        images = ec2.describe_images(
            Filters = [{
                "Name": "product-code",
                "Values": [PRODUCT_CODE]
            }]
        )['Images']
    except Exception:
        logging.exception("Failed to describe images")
        send_response(event, context, "FAILED")
        return

    if len(images) == 0:
        logging.error("No images were found")
        send_response(event, context, "FAILED")
        return

    latest = sorted(images, key=itemgetter('CreationDate'))[-1]['ImageId']
    logging.info(f"Latest '{PRODUCT_CODE}' AMI id - '{latest}'")
    send_response(event, context, "SUCCESS", {'Id': latest})