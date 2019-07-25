import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find unencrypted EBS volumes """
    set_logging(level=logging.INFO)
    logging.debug("Initiating unencrypted EBS volumes checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.ebsVolume.enabled:
            logging.debug("Unencrypted EBS volumes checking disabled")
            return

        logging.debug("Iterating over each account to initiate unencrypted EBS volumes checking")
        for account_id, account_name in config.ebsVolume.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating unencrypted EBS volume checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of unencrypted EBS volumes checking")
        return

    logging.debug("Unencrypted EBS volume checking initiation done")
