import os
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find RDS data encrypted or not """
    set_logging(level=logging.INFO)
    logging.debug("Initiating public RDS data encryption checking")

    try:
        sns_arn = os.environ["SNS_RDS_ENCRYPT_ARN"]
        config = Config()

        if not config.rdsEncrypt.enabled:
            logging.debug("Public RDS data encryption checking disabled")
            return

        logging.debug("Iterating each account to initiate RDS data encryption checking")
        for account_id, account_name in config.rdsEncrypt.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating public RDS data encryption checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of public RDS data encryption checking")
        return

    logging.debug("Public RDS data encryption checking initiation done")
