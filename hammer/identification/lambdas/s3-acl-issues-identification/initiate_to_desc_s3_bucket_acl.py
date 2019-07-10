import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find S3 bucket public access in ACL """
    set_logging(level=logging.INFO)
    logging.debug("Initiating S3 acls checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.s3acl.enabled:
            logging.debug("S3 acls checking disabled")
            return

        logging.debug("Iterating over each account to initiate s3 acls check")
        for account_id, account_name in config.s3acl.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                      }
            logging.debug(f"Initiating s3 acls checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of S3 acl checking")
        return

    logging.debug("S3 acls checking initiation done")
