import os
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find unencrypted elasticsearch domains """
    set_logging(level=logging.INFO)
    logging.debug("Initiating unencrypted Elasticsearch domains checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.esEncrypt.enabled:
            logging.debug("Elasticsearch unencrypted domains checking disabled")
            return

        logging.debug("Iterating each account to initiate Elasticsearch unencrypted domains checking")
        for account_id, account_name in config.esEncrypt.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating Elasticsearch unencrypted domains checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of Elasticsearch unencrypted domains checking")
        return

    logging.debug("Elasticsearch unencrypted domains checking initiation done")
