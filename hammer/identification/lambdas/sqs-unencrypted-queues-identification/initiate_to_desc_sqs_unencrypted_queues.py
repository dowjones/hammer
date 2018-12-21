import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find SQS unencrypted queues"""
    set_logging(level=logging.INFO)
    logging.debug("Initiating unencrypted SQS queues checking")

    try:
        sns_arn = os.environ["SNS_SQS_QUEUE_ARN"]
        config = Config()

        if not config.sqsEncrypt.enabled:
            logging.debug("unencrypted SQS queues checking disabled")
            return

        logging.debug("Iterating over each account to initiate unencrypted SQS queues check")
        for account_id, account_name in config.sqsEncrypt.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating unencrypted SQS queues checking for '{account_name}'")
            Sns.publish(sns_arn, payload)

    except Exception:
        logging.exception("Error occurred while initiation of unencrypted SQS queues checking")
        return

    logging.debug("Unencrypted SQS queues checking initiation done")
