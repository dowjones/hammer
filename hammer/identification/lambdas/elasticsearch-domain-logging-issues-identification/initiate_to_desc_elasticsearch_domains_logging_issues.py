import os
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find elasticsearch domains logging issue """
    set_logging(level=logging.INFO)
    logging.debug("Initiating Elasticsearch domains logging issue checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.esLogging.enabled:
            logging.debug("Elasticsearch domains logging issue checking disabled")
            return

        logging.debug("Iterating each account to initiate Elasticsearch domains logging issue checking")
        for account_id, account_name in config.esLogging.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating Elasticsearch domains logging issue checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of Elasticsearch domains logging issue checking")
        return

    logging.debug("Elasticsearch domains logging issue checking initiation done")
