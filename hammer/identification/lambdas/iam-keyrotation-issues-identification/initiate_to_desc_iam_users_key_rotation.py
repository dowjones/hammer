import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find stale keys for IAM users """
    set_logging(level=logging.INFO)
    logging.debug("Initiating IAM user keys rotation checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.iamUserKeysRotation.enabled:
            logging.debug("IAM user keys rotation checking disabled")
            return

        logging.debug("Iterating over each account to initiate IAM user keys rotation check")
        for account_id, account_name in config.iamUserKeysRotation.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                      }
            logging.debug(f"Initiating IAM user keys rotation checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of IAM user keys rotation check")
        return

    logging.debug("IAM user keys rotation checking initiation done")
