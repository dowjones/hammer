#!/usr/bin/env python3.6

import boto3
import json
import argparse
import secrets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fill ddb credentials')
    parser.add_argument("--table",
                        dest="table", default=None,
                        help="credentials DDB table name")
    parser.add_argument("--hammer-api-token",
                        dest="hammer_api_token", nargs='?', const=-1, type=str,
                        help="Hammer API token")
    parser.add_argument("--hammer-api-url",
                        dest="hammer_api_url", nargs='?', const=-1, type=str,
                        help="Hammer API url")
    parser.add_argument("--slack-api-token",
                        dest="slack_api_token", default=None,
                        help="Slack API token")
    parser.add_argument("--jira-key-cert-file",
                        dest="jira_key_cert_file", default=None,
                        help="Path to the file with a private key for JIRA")
    parser.add_argument("--jira-consumer-key",
                        dest="jira_consumer_key", default=None,
                        help="JIRA consumer key")
    parser.add_argument("--jira-access-token",
                        dest="jira_access_token", default=None,
                        help="JIRA access token")
    parser.add_argument("--jira-access-token-secret",
                        dest="jira_access_token_secret", default=None,
                        help="JIRA access token_secret")

    args = parser.parse_args()

    if args.table is None:
        print(f"credentials DDB table name should be set")
        exit(1)

    creds = {}
    if args.slack_api_token is not None:
        creds["slack"] = {"api_token": args.slack_api_token}


    if all(x is not None for x in [args.jira_key_cert_file,
                                   args.jira_consumer_key,
                                   args.jira_access_token,
                                   args.jira_access_token_secret]):
        with open(args.jira_key_cert_file, "rt") as fh:
            creds["jira"] = {
                "oauth": {
                    "key_cert": fh.read(),
                    "consumer_key": args.jira_consumer_key,
                    "access_token": args.jira_access_token,
                    "access_token_secret": args.jira_access_token_secret,
                }
            }

    if args.hammer_api_token != None:
        # generate new secret if secret value is not set
        creds["api"] = {"token": secrets.token_hex() if args.hammer_api_token == -1 else args.hammer_api_token}

    if args.hammer_api_url != None:
        creds["api"]["url"] = args.hammer_api_url

    if not creds:
        print(f"no credentials detected, please check CLI arguments")
        exit(1)

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(args.table)

    for service, credentials in creds.items():
        item={}
        item['service'] = service
        item['credentials'] = credentials
        table.put_item(Item=item)
        response = table.get_item(Key={'service': service})
        print("Successfully injected '{}' credentials: {}".format(service, json.dumps(response.get("Item", {}).get("credentials", {}), indent=4)))
