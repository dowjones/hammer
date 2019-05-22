import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find security groups unrestricted access """
    set_logging(level=logging.INFO)
    logging.debug("Initiating CloudTrail checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.cloudtrails.enabled:
            logging.debug("CloudTrail checking disabled")
            return

        logging.debug("Iterating over each account to initiate CloudTrail check")
        for account_id, account_name in config.cloudtrails.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating CloudTrail checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of CloudTrail checking")
        return

    logging.debug("CloudTrail checking initiation done")