import json
import logging
import os

from boto3 import resource
from boto3.dynamodb.conditions import Key, Attr
from enum import Enum
from library.aws.utility import Account
from library.config import Config
from library.ddb_issues import Operations, Issue, IssueStatus

class Issue_type(Enum):
    """
    enum class to map issue type to rule names
    provides a cleaner way to create unique issue ids
    for storage and query in whitelist database
    """
    def __str__(self):
        return str(self.value)

    cloudtrails = "cloudtrails"
    ebsSnapshot = "ebs_public_snapshot"
    ebsVolume = "ebs_unencrypted_volume"
    iamUserKeysRotation = "user_keysrotation"
    iamUserIpRestriction = "user_iprestriction"
    iamUserInactiveKeys = "user_inactivekeys"
    sg = "secgrp_unrestricted_access"
    s3policy = "s3_bucket_policy"
    s3acl = "s3_bucket_acl"
    iamUserWithPassword = "user_withpassword"
    rdsSnapshot = "rds_public_snapshot"
    sqspolicy = "sqs_public_access"
    s3Encrypt = "s3_encryption"
    rdsEncrypt = "rds_encryption"

class ddb_whitelist(object):

    def __init__(self, account_id, rule_name, issue_primary, *args):
        self.account_id = account_id
        #rule name maps to unique identifier in each dedscribe function
        self.rule_name = rule_name
        #Issues for json whitelist can take more than 1 Issues
        self.issue_id_primary = issue_primary
        self.issue_id_secondary = None
        self.issue_id_for_ddb_primary = self.issue_id_primary+"::"+Issue_type[self.rule_name].value
        self.whitelist_issue_first = Issue(self.account_id,self.issue_id_for_ddb_primary)

        #if more than one issue id types exist, check both
        if len(args)==1:
            self.issue_id_secondary = args[0]
            self.issue_id_for_ddb_secondary = self.issue_id_secondary+"::"+Issue_type[self.rule_name].value
            self.whitelist_issue_second = Issue(self.account_id,self.issue_id_for_ddb_secondary)

        self.config=Config()

        main_account = Account(region=self.config.aws.region)
        self.ddb_table = main_account.resource("dynamodb").Table(self.config.whitelistDDB.ddb_table_name)

    def is_whitelisted(self):
        """
        Query both json and ddb function
        return if issue present in either
        """
        if self.check_issue_in_whitelist_json() or self.check_issue_in_whitelist_ddb():
            return IssueStatus.Whitelisted
        else:
            return IssueStatus.Open

    def merge_whitelist_json_in_ddb(self):
        """
        Method to merge Whitelisted Json file entry with Dynamo db
        To have one source of truth for all whitelisted data
        Not used with current functionality
        """
        Operations.update(ddb_table,self.whitelist_issue)
        logging.debug(f"Adding json whitelist to ddb: {self.whitelist_issue}")
        return

    def check_issue_in_whitelist_json(self):
        """
        Check if issue exists on legagcy whitelist json file
        return Issue status if Existing
        else return nothing
        """
        try:
            if (getattr(self.config,self.rule_name).in_whitelist(self.account_id, self.issue_id_primary)) or \
                (getattr(self.config,self.rule_name).in_whitelist(self.account_id, self.issue_id_secondary)):
                    return IssueStatus.Whitelisted
        except:
            logging.debug(f"Secondary Issue probably not present: {self.account_id, self.issue_id_secondary}")
            pass

    def check_issue_in_whitelist_ddb(self):
        """
        Check if issue exists in the whitelist ddb
        corresponds to user selecting won't fix

        check for existence of both forms of issue ids and query ddb accordingly
        eg: sg.id or sg.vpc_id:sg.name
        """
        if self.ddb_table.query(KeyConditionExpression=Key('account_id').eq(self.whitelist_issue_first.account_id) & \
                                Key('issue_id').eq(self.whitelist_issue_first.issue_id))['Items']:
                                    return IssueStatus.Whitelisted

        elif self.issue_id_secondary and (self.ddb_table.query(KeyConditionExpression=Key('account_id').eq(self.whitelist_issue_second.account_id) & \
                                Key('issue_id').eq(self.whitelist_issue_second.issue_id))['Items']):
                                    return IssueStatus.Whitelisted
