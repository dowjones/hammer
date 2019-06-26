import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find clusters logging enabled or not. """
    set_logging(level=logging.INFO)
    logging.debug("Initiating Redshift Cluster logging checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.redshift_logging.enabled:
            logging.debug("Redshift cluster logging checking disabled")
            return

        logging.debug("Iterating over each account to initiate Redshift cluster logging check")
        for account_id, account_name in config.redshift_logging.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating Redshift cluster logging checking for '{account_name}'")
            Sns.publish(sns_arn, payload)

    except Exception:
        logging.exception("Error occurred while initiation of Redshift cluster logging checking")
        return

    logging.debug("Redshift clusters logging checking initiation done")
