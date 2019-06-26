import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find unencrypted Redshift clusters """
    set_logging(level=logging.INFO)
    logging.debug("Initiating Redshift Clusters checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.redshiftEncrypt.enabled:
            logging.debug("Redshift clusters checking disabled")
            return

        logging.debug("Iterating over each account to initiate Redshift Clusters check")
        for account_id, account_name in config.redshiftEncrypt.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating unencrypted Redshift clusters checking for '{account_name}'")
            Sns.publish(sns_arn, payload)

    except Exception:
        logging.exception("Error occurred while initiation of unencrypted Redshift cluster checking")
        return

    logging.debug("unencrypted Redshift clusters  checking initiation done")
