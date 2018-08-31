import json
import logging
import functools


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Account
from library.aws.security_groups import SecurityGroupsChecker


def logger(handler):
    @functools.wraps(handler)
    def wrapper(event, context):
        set_logging(level=logging.DEBUG)
        logging.debug(f"request:\n{json.dumps(event, indent=4)}")
        response = handler(event, context)
        logging.debug(f"response:\n{json.dumps(response, indent=4)}")
        return response
    return wrapper


def error_response(code, text):
    response = {"statusCode": code}
    if text:
        response['body'] = text
    return response

def server_error(text=""):
    return error_response(500, text)

def bad_request(text=""):
    return error_response(400, text)


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
                      role_name=config.aws.role_name_identification)
    if account.session is None:
        return server_error(text=f"Failed to create session in {account}")

    if security_feature == "secgrp_unrestricted_access":
        response = insecure_services(security_feature, config, account, ids, tags)
    else:
        response = f"asked to scan '{security_feature}' resources in '{region}' of '{account_id} / {account_name}'"

    return {
        "statusCode": 200,
        "body": json.dumps(response, indent=4) if isinstance(response, dict) else response
    }


def insecure_services(security_feature, config, account, ids, tags):
    checker = SecurityGroupsChecker(account=account,
                                    restricted_ports=config.sg.restricted_ports)
    result = []
    if checker.check(ids=ids, tags=tags):
        groups = []
        for sg in checker.groups:
            groups.append(f"{sg.name} / {sg.id}")
            if not sg.restricted:
                permissions = []
                for perm in sg.permissions:
                    for ip_range in perm.ip_ranges:
                        if not ip_range.restricted:
                            permissions.append({
                                'ports': f"{perm.to_port}" if perm.from_port == perm.to_port else f"{perm.from_port}-{perm.to_port}",
                                'protocol': perm.protocol,
                                'cidr': ip_range.cidr,
                            })
                result.append({
                    'id': sg.id,
                    'name': sg.name,
                    'status': sg.status.value,
                    'permissions': permissions,
                })
        response = {
            security_feature: result,
            'checked_groups': groups,
        }
        if ids:
            response.setdefault("filterby", {})["ids"] = ids
        if tags:
            response.setdefault("filterby", {})["tags"] = tags
        return response
    else:
        return server_error(text="Failed to check insecure services")
