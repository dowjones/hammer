#!/usr/bin/env python3.6

import boto3
import argparse
import secrets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fill ddb credentials')
    parser.add_argument("table", help="credentials DDB table name")
    parser.add_argument("username", type=str, help='API user name')
    parser.add_argument("--token", type=str, dest='token', default='',
                        help='Token that is used to authenticate API requests')
    parser.add_argument("--accounts", type=str, dest='accounts',
                        help="Accounts that is accessible for scan for this user. Please use comma as a separator. "
                             "By default, all accounts are accessible")

    args = parser.parse_args()

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(args.table)

    api_creds = table.get_item(Key={'service': 'api'})['Item']
    if not api_creds:
        api_creds = {'service': 'api', 'credentials': {'tokens': {}}}
    if 'tokens' in api_creds['credentials']:
        tokens = api_creds['credentials']['tokens']
    else:
        api_creds['credentials']['tokens'] = {}
        tokens = api_creds['credentials']['tokens']
    token = args.token
    if not token:
        token = secrets.token_hex()
    current_token = None
    for k in tokens:
        if tokens[k]['username'] == args.username:
            current_token = k
    if current_token:
        tokens.pop(current_token)

    if not args.accounts:
        accounts = []
    else:
        accounts = args.accounts.split(',')
    tokens[token] = {}
    tokens[token]['accounts'] = {args.accounts}
    tokens[token]['username'] = args.username

    table.put_item(Item=api_creds)
    print('Successfully added new user to DDB')
