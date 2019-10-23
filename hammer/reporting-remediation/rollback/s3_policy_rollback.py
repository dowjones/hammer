import logging

from library.config import Config
from library.aws.utility import Account
from library.aws.s3 import S3Operations


class S3UpdatePolicy:

    def __init__(self, config):
        self.config = config

    def s3_policy(self, batch=False):

        # update account details and policy statement details from JIRA ticket for rollback
        account_id = ""
        account_name = ""
        bucket_name = ""

        account = Account(id=account_id,
                          name=account_name,
                          role_name=self.config.aws.role_name_reporting)
        policy_doc = {}
        statement = {}
        statement["Effect"] = ""
        statement["Principal"] = ""
        statement["Action"] = ""
        statement["Resource"] = ""

        policy_doc["Statement"] = statement

        S3Operations.put_bucket_policy(account.client("s3"), bucket_name, policy_doc)


if __name__ == "__main__":
    config = Config()

    try:
        class_object = S3UpdatePolicy(config)
        class_object.s3_policy()
    except Exception:
        logging.exception("Failed to clean S3 public policies")
