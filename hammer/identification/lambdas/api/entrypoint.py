import json
import logging
import functools
import importlib


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Account
from responses import bad_request, server_error


def logger(handler):
    @functools.wraps(handler)
    def wrapper(event, context):
        set_logging(level=logging.DEBUG)
        logging.debug(f"request:\n{json.dumps(event, indent=4)}")
        response = handler(event, context)
        logging.debug(f"response:\n{json.dumps(response, indent=4)}")
        return response
    return wrapper


@logger
def lambda_handler(event, context):
    try:
        payload = json.loads(event.get('body', "{}"))
    except Exception:
        logging.exception("failed to parse payload")
        return bad_request(text="malformed payload")

    if not payload:
        return bad_request(text="empty payload")

    account_id = payload.get("account_id", None)
    region = payload.get("region", None)
    security_feature = payload.get("security_feature", None)
    tags = payload.get("tags", None)
    ids = payload.get("ids", None)

    config = Config()

    action = event.get("path", "")[1:]
    # do not forget to allow path in authorizer.py while extending this list
    if action == "identify":
        role = config.aws.role_name_identification
    elif action == "remediate":
        role = config.aws.role_name_reporting
    else:
        return bad_request(text="wrong action")

    account_name = config.aws.accounts.get(account_id, None)

    if account_name is None:
        return bad_request(text=f"account '{account_id}' is not defined")

    if not all([account_id, security_feature]):
        return bad_request(text="wrong payload, missing required parameter")

    valid_security_features = [ module.section for module in config.modules ]
    if security_feature not in valid_security_features:
        return bad_request(text=f"wrong security feature - '{security_feature}', available choices - {valid_security_features}")

    if ids is not None and not isinstance(ids, list):
        return bad_request(text=f"'ids' parameter must be list")

    if tags is not None and not isinstance(tags, dict):
        return bad_request(text=f"'tags' parameter must be dict")

    account = Account(id=account_id,
                      name=account_name,
                      region=region,
                      role_name=role)
    if account.session is None:
        return server_error(text=f"Failed to create session in {account}")

    try:
        module = importlib.import_module(security_feature)
        handler = getattr(module, action)
    except (ModuleNotFoundError, AttributeError):
        logging.exception("Module or attribute was not found")
        response = f"{action} for '{security_feature}' resources in '{region}' of '{account_id} / {account_name}' is not implemented yet"
    else:
        try:
            response = handler(security_feature, account, config, ids, tags)
        except Exception:
            text=f"{security_feature}:{action} execution error"
            logging.exception(text)
            return server_error(text=text)

    return {
        "statusCode": 200,
        "body": json.dumps(response, indent=4) if isinstance(response, dict) else response
    }