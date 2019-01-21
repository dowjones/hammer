import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to Initiating to get CNAME recordsets """
    set_logging(level=logging.DEBUG)
    logging.debug("Initiating to get CNAME recordsets")

    try:
        sns_arn = os.environ["SNS_DNS_TAKEOVER_ARN"]
        config = Config()

        logging.debug("Iterating over each account to get cname recordsets")
        for account_id, account_name in config.cnameRecordsets.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                      }
            logging.debug(f"Initiating to get CNAME recordsets for account'{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of retrieving CNAME recordsets")
        return

    logging.debug("CNAME recordsets retrieving initiation done")
