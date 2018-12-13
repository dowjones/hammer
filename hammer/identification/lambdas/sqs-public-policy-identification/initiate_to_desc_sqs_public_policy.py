import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find SQS public access in policy """
    set_logging(level=logging.INFO)
    logging.debug("Initiating SQS policies checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.sqspolicy.enabled:
            logging.debug("SQS policies checking disabled")
            return

        logging.debug("Iterating over each account to initiate SQS policies check")
        for account_id, account_name in config.sqspolicy.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating SQS policies checking for '{account_name}'")
            Sns.publish(sns_arn, payload)

    except Exception:
        logging.exception("Error occurred while initiation of SQS policy checking")
        return

    logging.debug("SQS policies checking initiation done")
