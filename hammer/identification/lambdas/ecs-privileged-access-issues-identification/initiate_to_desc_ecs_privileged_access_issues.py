import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find privileged access enabled or not. """
    set_logging(level=logging.INFO)
    logging.debug("Initiating ECS privileged access checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.ecs_privileged_access.enabled:
            logging.debug("ECS privileged access checking disabled")
            return

        logging.debug("Iterating over each account to initiate ECS privileged access check")
        for account_id, account_name in config.ecs_privileged_access.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating ECS privileged access checking for '{account_name}'")
            Sns.publish(sns_arn, payload)

    except Exception:
        logging.exception("Error occurred while initiation of ECS privileged access checking")
        return

    logging.debug("ECS privileged access checking initiation done")
