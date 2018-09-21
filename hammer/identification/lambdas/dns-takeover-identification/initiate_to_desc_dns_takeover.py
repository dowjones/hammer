import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find DNS takeover issues """
    set_logging(level=logging.DEBUG)
    logging.debug("Initiating DNS takeover issue identification")

    try:
        sns_arn = os.environ["SNS_DNS_TAKEOVER_ARN"]
        config = Config()

        if not config.dnsTakeover.enabled:
            logging.debug("DNS Takeover issues identification disabled")
            return

        logging.debug("Iterating over each account to initiate dns takeover check")
        for account_id, account_name in config.dnsTakeover.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                      }
            logging.debug(f"Initiating dns takeover checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of DNS takeover checking")
        return

    logging.debug("DNS takeover checking initiation done")
