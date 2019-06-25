import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find ecs task definitions' image source external or internal. """
    set_logging(level=logging.INFO)
    logging.debug("Initiating ECS task definitions' image source checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.ecs_external_image_source.enabled:
            logging.debug("ECS task definitions' image source checking disabled")
            return

        logging.debug("Iterating over each account to initiate ECS task definitions' image source check")
        for account_id, account_name in config.ecs_external_image_source.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "regions": config.aws.regions,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating ECS task definitions' image source checking for '{account_name}'")
            Sns.publish(sns_arn, payload)

    except Exception:
        logging.exception("Error occurred while initiation of ECS task definitions' image source checking")
        return

    logging.debug("ECS task definitions' image source checking initiation done")
