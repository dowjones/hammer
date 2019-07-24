import os
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find public RDS snapshots """
    set_logging(level=logging.INFO)
    logging.debug("Initiating public RDS snapshots checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.rdsSnapshot.enabled:
            logging.debug("Public RDS snapshots checking disabled")
            return

        logging.debug("Iterating each account to initiate RDS snapshots checking")
        for account_id, account_name in config.rdsSnapshot.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating public RDS snapshots checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of public RDS snapshots checking")
        return

    logging.debug("Public RDS snapshot checking initiation done")
