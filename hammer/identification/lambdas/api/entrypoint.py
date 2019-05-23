import functools
import json
import logging
import uuid
import time

import boto3

from library.aws.utility import Account, DDB, Sns
from library.config import Config
from library.ddb_issues import Operations as IssueOperations
from library.logger import set_logging
from library import utility
from responses import bad_request


def logger(handler):
    @functools.wraps(handler)
    def wrapper(event, context):
        set_logging(level=logging.DEBUG)
        logging.debug(f"request:\n{json.dumps(event, indent=4)}")
        response = handler(event, context)
        logging.debug(f"response:\n{json.dumps(response, indent=4)}")
        return response
    return wrapper


def get_sns_topic_arn(config, topic_name):
    # it assumes that lambda and sns are in the same region
    region = config.aws.region
    account_id = boto3.client('sts').get_caller_identity()['Account']
    return f"arn:aws:sns:{region}:{account_id}:{topic_name}"


GLOBAL_SECURITY_FEATURES = ['s3_bucket_acl', 'user_inactivekeys', 'user_keysrotation', 's3_bucket_policy',
                            's3_encryption']


def start_scan(account_id, regions, security_features, tags, ids):
    config = Config()

    account_name = config.aws.accounts.get(account_id, None)

    if not account_id:
        return bad_request(text="account_id is required parameter")

    if account_name is None:
        return bad_request(text=f"account '{account_id}' is not defined")

    valid_security_features = [ module.section for module in config.modules ]
    for security_feature in security_features:
        if security_feature not in valid_security_features:
            return bad_request(
                text=f"wrong security feature - '{security_feature}', available choices - {valid_security_features}")

    if not security_features:
        security_features = valid_security_features

    all_regions = config.aws.regions

    for region in regions:
        if region not in all_regions:
            return bad_request(text=f"Region '{region} is not supported")
    # empty list means we want to scan all supported regions
    if not regions:
        regions = all_regions

    if ids is not None and not isinstance(ids, list):
        return bad_request(text=f"'ids' parameter must be list")

    if tags is not None and not isinstance(tags, dict):
        return bad_request(text=f"'tags' parameter must be dict")

    main_account = Account(region=config.aws.region)
    api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
    to_scan = []
    for security_feature in security_features:
        accounts = config.get_module_config_by_name(security_feature).accounts
        if account_id in accounts:
            to_scan.append(security_feature)
    regional_services = set(to_scan) - set(GLOBAL_SECURITY_FEATURES)
    global_services = set(to_scan).intersection(set(GLOBAL_SECURITY_FEATURES))
    total = len(regional_services) * len(regions) + len(global_services)
    request_params = {
        "account_id": account_id,
        "regions": regions,
        "security_features": to_scan,
        "tags": tags
    }
    request_id = uuid.uuid4().hex

    DDB.add_request(api_table, request_id, request_params, total)

    for security_feature in to_scan:
        topic_name = config.get_module_config_by_name(security_feature).sns_topic_name
        topic_arn = get_sns_topic_arn(config, topic_name)
        payload = {
            "account_id": account_id,
            "account_name": account_name,
            "regions": regions,
            "sns_arn": topic_arn,
            "request_id": request_id
        }
        Sns.publish(topic_arn, payload)

    response = {'request_id': request_id}

    return {
        "statusCode": 200,
        "body": json.dumps(response, indent=4) if isinstance(response, dict) else response
    }


def collect_results(request_info, main_account):
    security_features = request_info['request_params']['security_features']
    regions = request_info['request_params']['regions']
    scan_account_id = request_info['request_params']['account_id']
    tags = request_info['request_params']['tags']
    response = dict({'global': {}})
    for region in regions:
        response[region] = {}
        for sec_feature in security_features:
            if sec_feature not in GLOBAL_SECURITY_FEATURES:
                response[region][sec_feature] = []
            else:
                response['global'][sec_feature] = []

    config = Config()
    for security_feature in security_features:
        sec_feature_config = config.get_module_config_by_name(security_feature)
        ddb_table = main_account.resource("dynamodb").Table(sec_feature_config.ddb_table_name)
        for issue in IssueOperations.get_account_open_issues(ddb_table, scan_account_id):
            if issue.contains_tags(tags) and (
                    issue.issue_details.region in regions or security_feature in GLOBAL_SECURITY_FEATURES):
                issue_region = issue.issue_details.region if issue.issue_details.region else 'global'
                response[issue_region][security_feature].append({'id': issue.issue_id,
                                                                 'issue_details': issue.issue_details.as_dict()})
    return response


def get_scan_results(request_id):
    config = Config()
    main_account = Account(region=config.aws.region)
    api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
    request_info = DDB.get_request_data(api_table, request_id)
    if not request_info:
        status_code = 404
        body = {"message": "Request id has not been found."}
    elif request_info['progress'] == request_info['total']:
        status_code = 200
        body = {
            "scan_status": "COMPLETE",
            "scan_results": collect_results(request_info, main_account)
        }
    elif time.time() - request_info['updated'] <= 300:
        status_code = 200
        body = {
            "scan_status": "IN_PROGRESS"
        }
    else:
        status_code = 200
        body = {
            "scan_status": "FAILED"
        }
    return {
        "statusCode": status_code,
        "body": json.dumps(body, indent=4, default=utility.jsonEncoder)
    }


@logger
def lambda_handler(event, context):
    try:
        body = event.get('body') if event.get('body') else "{}"
        payload = json.loads(body)
    except Exception:
        logging.exception("failed to parse payload")
        return bad_request(text="malformed payload")

    account_id = payload.get("account_id", None)
    regions = payload.get("regions", [])
    security_features = payload.get("security_features", [])
    tags = payload.get("tags", None)
    ids = payload.get("ids", None)

    action = event.get("path", "")[1:]
    method = event.get("httpMethod")
    # do not forget to allow path in authorizer.py while extending this list
    if action.startswith('identify'):
        if method == "POST":
            return start_scan(account_id, regions, security_features, tags, ids)
        if method == "GET":
            # get request id from url path
            request_id = action.split('/')[1]
            return get_scan_results(request_id)
    else:
        return bad_request(text="wrong action")
