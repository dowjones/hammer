import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find inactive keys for IAM users """
    set_logging(level=logging.INFO)
    logging.debug("Initiating IAM user inactive keys checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.iamUserInactiveKeys.enabled:
            logging.debug("IAM user inactive keys checking disabled")
            return

        logging.debug("Iterating over each account to initiate IAM user inactive keys check")
        for account_id, account_name in config.iamUserInactiveKeys.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                      }
            logging.debug(f"Initiating IAM user inactive keys checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of IAM user inactive keys check")
        return

    logging.debug("IAM user inactive keys checking initiation done")
