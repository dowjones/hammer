import os
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find publicly accessible elasticsearch domains """
    set_logging(level=logging.INFO)
    logging.debug("Initiating publicly accessible Elasticsearch domains checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.esPublicAccess.enabled:
            logging.debug("Elasticsearch publicly accessible domains checking disabled")
            return

        logging.debug("Iterating each account to initiate Elasticsearch publicly accessible domains checking")
        for account_id, account_name in config.esPublicAccess.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating Elasticsearch publicly accessible domains checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of Elasticsearch publicly accessible domains checking")
        return

    logging.debug("Elasticsearch publicly accessible domains checking initiation done")
