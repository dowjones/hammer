import json
import logging

from datetime import datetime, timezone
from library.logger import set_logging
from library.config import Config
from library.aws.utility import Account
from library.aws.s3 import S3Operations


def lambda_handler(event, context):
    """ Lambda handler to cname record_sets details."""
    set_logging(level=logging.DEBUG)

    try:
        payload = json.loads(event["Records"][0]["Sns"]["Message"])
        account_id = payload['account_id']
        account_name = payload['account_name']
    except Exception:
        logging.exception(f"Failed to parse event\n{event}")
        return

    try:
        config = Config()

        main_account = Account(region=config.aws.region)

        backup_bucket = config.aws.s3_backup_bucket

        account = Account(id=account_id,
                          name=account_name,
                          role_name=config.aws.role_name_identification)
        if account.session is None:
            return

        matching_record_sets = config.cnameRecordsets.matching_record_sets

        s3client = main_account.client("s3"),
        upload_cname_record_sets(s3client, account, backup_bucket, matching_record_sets)

    except Exception:
        logging.exception(f"Failed to get record_sets for '{account_id} ({account_name})'")
        return

    logging.debug(f"Completed record_set for '{account_id} ({account_name})'")


def upload_cname_record_sets(s3_client, account, bucket, matching_record_sets):
    resulted_record_sets = {}
    client = account.client("route53")

    hosted_zones_res = client.list_hosted_zones()
    for hosted_zone in hosted_zones_res["HostedZones"]:
        id = hosted_zone["Id"]
        resource_record_sets = client.list_resource_record_sets(
            HostedZoneId=id
        )
        record_sets = {}
        for resource_record_set in resource_record_sets["ResourceRecordSets"]:
            name = resource_record_set["Name"]
            type = resource_record_set["Type"]

            if type == "CNAME":
                for record_set in matching_record_sets:
                    if record_set in name:
                        record_sets[record_set] = resource_record_set["ResourceRecords"]
        if bool(record_sets):
            resulted_record_sets[id] = record_sets

        if bool(resulted_record_sets):
            timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
            # this prefix MUST match prefix in find_source_s3
            path = f"hosted_zones/{account.id}/{id}_{timestamp}.json"
            if S3Operations.object_exists(s3_client, bucket, path):
                raise Exception(f"s3://{bucket}/{path} already exists")
            S3Operations.put_object(s3_client, bucket, path, resulted_record_sets)



