import os
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find public EBS snapshots """
    set_logging(level=logging.INFO)
    logging.debug("Initiating public EBS snapshots checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.ebsSnapshot.enabled:
            logging.debug("Public EBS snapshots checking disabled")
            return

        logging.debug("Iterating each account to initiate EBS snapshots checking")
        for account_id, account_name in config.ebsSnapshot.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating public EBS snapshots checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of public EBS snapshots checking")
        return

    logging.debug("Public EBS snapshot checking initiation done")
