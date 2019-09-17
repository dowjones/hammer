import os
import logging
import time

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns
from library.aws.utility import Account

def lambda_handler(event, context):
    """ Lambda handler to initiate to find SQS public access in policy """
    set_logging(level=logging.INFO)
    logging.debug("Initiating SQS policies checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.trustedAdvisor.enabled:
            logging.debug("TA policies checking disabled")
            return

    except Exception:
        logging.exception("Failed to parse config")
        return

    logging.debug("Iterating over each check to grab specified accounts")

    account_and_checks = {}

    for config_check in config.trustedAdvisor.checks:
        list_of_accounts_per_check = config_check["accounts"]
        checkname = config_check["checkname"]
        ddb = config_check["ddb.table_name"]
        filters = config_check["filters"]
        name = config_check["name"]
        category = config_check["category"]

        for account_id in list_of_accounts_per_check:

            if (account_and_checks.get(account_id) is None):

                client = Account(id=account_id, region="us-east-1").client("support")
                account_and_checks.update({account_id: {"account_id" : account_id, "client": client, "checks_info": []}
                })

            check_response = account_and_checks.get(account_id).get("client").describe_trusted_advisor_checks(language='en')

            for ck in check_response["checks"]:
                if ck["name"] == checkname:
                    check_info = ck
            try:
                check_id = check_info['id']
                metadata = check_info['metadata']
                check_id_obj = {"checkname" : checkname, "id" : check_id, "name": name, "category": category, "metadata" : metadata, "ddb.table_name" : ddb, "filters": filters, "refresh_done" : False}
                account_and_checks.get(account_id)["checks_info"].append(check_id_obj)

            except:
                logging.exception("No check to match checkname given")
                return
            account_and_checks.get(account_id).get("client").refresh_trusted_advisor_check(checkId=check_id)

    timeout = config.trustedAdvisor.refreshtimeout*60
    start = time.time()

    while True:
        all_refreshes_done = True
        for acct in account_and_checks:
            current_account_obj = account_and_checks[acct]
            for chk in current_account_obj["checks_info"]:
                if chk["refresh_done"] == False:
                    status = current_account_obj["client"].describe_trusted_advisor_check_refresh_statuses(checkIds=[chk["id"]])
                    if not status["statuses"][0]["status"] == "success":
                        all_refreshes_done = False
                    else:
                        chk["refresh_done"] = True
                else:
                    break
        end = time.time()
        if all_refreshes_done == True or end - start >= timeout:
            break

    for account in account_and_checks:
        try:
            acc = account_and_checks[account]
            payload = { "account_id": acc["account_id"],
                        "checks": acc["checks_info"]
            }
            logging.debug("Initiating TA describe")
            Sns.publish(sns_arn, payload)

        except Exception:
            logging.exception("Error occurred while initiation of SNS")
            return

    logging.debug("TA initiation done")

