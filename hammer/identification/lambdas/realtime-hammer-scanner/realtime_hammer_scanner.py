import json
import logging
import io

from library.logger import set_logging
from botocore.vendored import requests
from library.config import Config
from gzip import GzipFile
from library.utility import CloudTrailParser


def lambda_handler(event, context):

    set_logging(level=logging.DEBUG)
    ### Read the SNS notification and retrieve the s3 bucket and the object where the cloudtrail info is located
    try:
        message = json.loads(event['Records'][0]['body'])
        config = Config()
        api_endpoint = config.api.url
        api_token = config.api.token

        ### Load the cloudwatch mappings
        with open('realtime_hammer_mapping.json', 'r') as json_file:
            cloudwatch_mapping = json.load(json_file)

    except Exception:
        logging.exception(f"Failed to parse cloudwatch mapping\n")
        return

    ### Parse through the message in and find the eventName to kick off specific hammer rules
    try:
        cloud_trail = CloudTrailParser(message)
        scan = cloudwatch_mapping[cloud_trail.event]
        user_id = cloud_trail.userArn
        account_id = cloud_trail.accountID
        logging.debug(cloud_trail)
        payload = {
            'account_id': cloud_trail.accountID,
            'security_features': scan,
            'tags': {
                'user_id': cloud_trail.userArn,
                'invocation_reason': cloud_trail.event,
                'resource': cloud_trail.resource,
                'object_key': cloud_trail.objectKey,
                'region': cloud_trail.region,
                'event_time': cloud_trail.eventTime,
                'raw': cloud_trail.message
            }
        }
        ### If there is a region specified, scan only that specific region
        if cloud_trail.region:
            payload['regions'] = [cloud_trail.region]


        url = api_endpoint + 'identify'
        logging.debug(url)
        headers = {
                'Auth':api_token,
                'content-type': 'application/json'
                }
        logging.debug(f"Initiating Realtime Scan for ' {payload}'")
        r = requests.post(url, data=json.dumps(payload), headers=headers)
        logging.debug(r)
    except Exception:
       logging.exception(f"The following CloudTrail eventName is not currently supported {message}")
