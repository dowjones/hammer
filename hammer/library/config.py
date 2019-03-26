import boto3
import json
import logging
import configparser
import re
import os
import requests


from functools import lru_cache
from datetime import datetime, timedelta, timezone


class Config(object):
    """
    Basic class do deal with hammer configuration.
    It takes uses local file to construct config object.
    """
    def __init__(self,
                 configFile="config.json",
                 configIniFile="config.ini",
                 whitelistFile="whitelist.json",
                 fixnowFile="fixnow.json",
                 ticketOwnersFile="ticket_owners.json"):
        """
        :param configFile: local path to configuration file in json format
        :param configIniFile: local path to configuration file in ini format (is used in r&r EC2, build from EC2 userdata)
        :param whitelistFile: local path to whitelist file in json format
        :param fixnowFile: local path to fixnow file in json format
        :param ticketOwnersFile: local path to file with default ticket owners by bu/account in json format
        """

        self._config = self.json_load_from_file(configFile)
        self._config['whitelist'] = self.json_load_from_file(whitelistFile, default={})
        self._config['fixnow'] = self.json_load_from_file(fixnowFile, default={})

        self.local = LocalConfig(configIniFile)
        self.owners = OwnersConfig(self.json_load_from_file(ticketOwnersFile, default={}))
        self.cronjobs = self._config.get('cronjobs', {})
        self.aws = AWSConfig(self._config)
        # security group issue config
        self.sg = ModuleConfig(self._config, "secgrp_unrestricted_access")
        # CloudTrails issue config
        self.cloudtrails = ModuleConfig(self._config, "cloudtrails")
        # S3 policy issue config
        self.s3policy = ModuleConfig(self._config, "s3_bucket_policy")
        # S3 ACL issue config
        self.s3acl = ModuleConfig(self._config, "s3_bucket_acl")
        # IAM inactive keys issue config
        self.iamUserInactiveKeys = IAMUserInactiveKeysConfig(self._config, "user_inactivekeys")
        # IAM keys rotation issue config
        self.iamUserKeysRotation = IAMUserKeysRotationConfig(self._config, "user_keysrotation")
        # EBS unencrypted volume issue config
        self.ebsVolume = ModuleConfig(self._config, "ebs_unencrypted_volume")
        # EBS public snapshot issue config
        self.ebsSnapshot = ModuleConfig(self._config, "ebs_public_snapshot")
        # RDS public snapshot issue config
        self.rdsSnapshot = ModuleConfig(self._config, "rds_public_snapshot")
        # SQS public access issue config
        self.sqspolicy = ModuleConfig(self._config, "sqs_public_access")
        # S3 encryption issue config
        self.s3Encrypt = ModuleConfig(self._config, "s3_encryption")
        # RDS encryption issue config
        self.rdsEncrypt = ModuleConfig(self._config, "rds_encryption")

        # AMI public access issue config
        self.publicAMIs = ModuleConfig(self._config, "ec2_public_ami")

        self.bu_list = self._config.get("bu_list", [])
        self.whitelisting_procedure_url = self._config.get("whitelisting_procedure_url", None)

        jira_config = self._config.get('jira', {})
        # credentials to access JIRA
        jira_config["credentials"] = self.json_load_from_ddb(self._config["credentials"]["ddb.table_name"],
                                                             self.aws.region,
                                                             "jira")
        self.jira = JiraConfig(jira_config)

        slack_config = self._config.get('slack', {})
        # credentials to access Slack
        slack_config["credentials"] = self.json_load_from_ddb(self._config["credentials"]["ddb.table_name"],
                                                              self.aws.region,
                                                              "slack")
        # Slack configuration
        self.slack = SlackConfig(slack_config)
        # CSV configuration
        self.csv = CSVConfig(self._config, self.slack)

        # API configuration
        self.api = ApiConfig({
            'credentials':  self.json_load_from_ddb(self._config["credentials"]["ddb.table_name"],
                                                    self.aws.region,
                                                    "api"),
            'table': self._config["api"]["ddb.table_name"]
        })

    def get_bu_by_name(self, name):
        """
        Guess BU value from the issue name

        :param name: string with issue name to check BU in

        :return: string with BU value or None
        """
        for bu in self.bu_list:
            if bu in name:
                return bu
        return None

    @property
    def modules(self):
        """
        :return: list with issue configuration modules
        """
        return [value for value in vars(self).values() if isinstance(value, ModuleConfig)]

    @property
    def now(self):
        return datetime.now(timezone.utc)

    def get_module_config_by_name(self, name):
        for module in self.modules:
            if module.name == name:
                return module

    def json_load_from_file(self, filename, default=None):
        """
        Loads json from config file to dictionary.

        :param filename: file name to load config from
        :param default: default value in case if file was not found/failed to parse

        :return: dict with config file content or default value

        .. note:: can raise exception if file can't be loaded/parsed and default is not set
        """
        try:
            with open(filename, "rb") as fh:
                config2load = fh.read()
                return json.loads(config2load)
        except Exception as err:
            if default is not None:
                return default
            else:
                logging.error(f"can't get config from {filename}\n{err}")
                raise

    def json_load_from_ddb(self, table, region, key):
        """
        Loads json from DDB table.

        :param table: str, DDB table name to search config in
        :param region: str, DDB table region
        :param key: 'service' key to get config from

        :return: dict with config content from DDB

        .. note:: return empty dict in case of errors
        """
        try:
            dynamodb = boto3.resource('dynamodb', region_name=region)
            table = dynamodb.Table(table)
            response = table.get_item(Key={'service': key})
            return response.get("Item", {}).get("credentials", {})
        except Exception as err:
            logging.warning(f"Failed to load json from DDB '{table}' with '{key}' key\n{err}")
            return {}

    @property
    def source(self):
        """ :return: pretty formatted of main config.json """
        return json.dumps(self._config, indent=4)


class OwnersConfig(object):
    """
    Helps to look for JIRA ticket owner and parent ticket in config file (ticket_owners.json).
    """
    def __init__(self, owners):
        """
        :param owners: content of `ticket_owners.json`
        """
        self.owners = owners

    def ticket_prop(self, prop, bu=None, product=None, account=None):
        """
        :param prop: property to search for
        :param bu: `business unit` tag
        :param product: `product` tag
        :param account: AWS account Id

        :return: ticket property based on business unit, product, AWS account or None
        """
        in_product = self.owners.get("bu", {}).get(bu, {}).get("product", {}).get(product, {}).get(prop, None)
        if in_product:
            logging.debug(f"Found '{prop}' in bu/product: {in_product}")
            return in_product

        in_bu = self.owners.get("bu", {}).get(bu, {}).get(prop, None)
        if in_bu:
            logging.debug(f"Found '{prop}' in bu: {in_bu}")
            return in_bu

        in_account = self.owners.get("account", {}).get(account, {}).get(prop, None)
        if in_account:
            logging.debug(f"Found '{prop}' in account: {in_account}")
            return in_account

        default = self.owners.get(prop, None)
        logging.debug(f"Failed to find '{prop}', returning default: {default}")
        return default


    def ticket_owner(self, bu=None, product=None, account=None):
        """
        :param bu: `business unit` tag
        :param product: `product` tag
        :param account: AWS account Id

        :return: ticket owner based on business unit, product, AWS account or None
        """
        return self.ticket_prop("jira_owner", bu, product, account)

    def slack_owner(self, bu=None, product=None, account=None):
        """
        :param bu: `business unit` tag
        :param product: `product` tag
        :param account: AWS account Id

        :return: list with slack owners based on business unit, product, AWS account
        """
        owner = self.ticket_prop("slack_owner", bu, product, account)
        if owner is not None:
            if isinstance(owner, str):
                owner = [owner]
            elif isinstance(owner, list):
                # make a copy of list from config as it will be changed later,
                # making changes in original list
                owner = owner[:]
            return owner
        else:
            return []

    def ticket_parent(self, bu=None, product=None, account=None):
        """
        :param bu: `business unit` tag
        :param product: `product` tag
        :param account: AWS account Id

        :return: parent ticket Id based on business unit, product, AWS account or None
        """
        return self.ticket_prop("jira_parent_ticket", bu, product, account)

    def ticket_project(self, bu=None, product=None, account=None):
        """
        :param bu: `business unit` tag
        :param product: `product` tag
        :param account: AWS account Id

        :return: JIRA project name based on business unit, product, AWS account or None
        """
        return self.ticket_prop("jira_project", bu, product, account)


class JiraConfig(object):
    """ Base class for JIRA """
    def __init__(self, config):
        self._config = config

    @property
    def enabled(self):
        """ :return: boolean, if Jira integration should be used """
        return self._config.get("enabled", False)

    @property
    def text_field_character_limit(self):
        return self._config.get("text_field_character_limit", 0)

    def __getattr__(self, key):
        """ Search for any attribute in config, if not found - raise exception """
        if key in self._config:
            return self._config[key]
        raise AttributeError(f"section 'jira' has no option '{key}'")


class ApiConfig(object):
    def __init__(self, config):
        self._config = config

    @property
    def token(self):
        return self._config.get("credentials", {}).get("token", None)

    @property
    def url(self):
        return self._config.get("credentials", {}).get("url", None)

    @property
    def ddb_table_name(self):
        return self._config['table']


class SlackConfig(object):
    """ Base class for Slack logging """
    def __init__(self, config):
        self._config = config
        # default channel to log
        self.default_channel = self._config.get("default_channel", None)
        # channels to log matched messages to based on RE patterns (per-compile them for faster search)
        self.channels = {}
        for channel, patterns in self._config["channels"].items():
            self.channels[channel] = [ re.compile(pattern) for pattern in patterns ]
        self.ignore = [ re.compile(pattern) for pattern in self._config.get("ignore", []) ]

    def find_channel(self, msg):
        """
        Find a Slack channel to send message to based on message body

        :param msg: message body to match

        :return: string with channel name or None
        """
        # ignore messages based on patterns from config
        for pattern in self.ignore:
            if pattern.search(msg):
                return None

        # find channel to log message to based on message content
        for channel, patterns in self.channels.items():
            for pattern in patterns:
                if pattern.search(msg):
                    return channel

        return self.default_channel

    @property
    def notify_default_owner(self):
        return self._config.get('notify_default_owner', True)

    @property
    def enabled(self):
        return self._config.get('enabled', False)

    @property
    def api_token(self):
        return self._config.get("credentials", {}).get("api_token", "")


class LocalConfig(object):
    """ r&r EC2 local config in ini format. Assumes plain structure without sections, only options """
    def __init__(self, inifile):
        try:
            self.cfg = configparser.ConfigParser()
            with open(inifile, "rt") as fh:
                ini = fh.read()
        except Exception:
            pass
        else:
            self.cfg.read_string(f"[default]\n{ini}")

    def __getattr__(self, key):
        """ Search for any attribute in config, if not found - return None """
        try:
            return self.cfg.get("default", key)
        except configparser.NoSectionError:
            return None
        except configparser.NoOptionError:
            logging.warning(f"Local config has no option '{key}'")
            return None


class BaseConfig(object):
    """ Base class for configuration file sections """
    def __init__(self, config, section):
        # name of the current section
        self.section = section
        # part of config dict for given section
        self._config = config[section]

    def __getattr__(self, key):
        """ Search for any attribute in config, if not found - raise exception """
        if key in self._config:
            return self._config[key]
        raise AttributeError(f"section '{self.section}' has no option '{key}'")


class CSVConfig(BaseConfig):
    """ represents CSV configuration part in config.json """
    def __init__(self, config, slack_config):
        super().__init__(config, "csv")
        self.slack_config = slack_config

    @property
    def slack_channel(self):
        return self._config.get("slack_channel") or self.slack_config.default_channel


class AWSConfig(BaseConfig):
    """ represents AWS configuration part in config.json """
    def __init__(self, config):
        super().__init__(config, "aws")

    @property
    @lru_cache()
    def region(self):
        """
        Autodetection of current AWS region for AWS Lambda and EC2.

        :return: string with AWS region the code is running in
        """
        # running in Lambda
        region = os.environ.get("AWS_DEFAULT_REGION")
        if region is not None:
            return region

        try:
            # running in EC2
            response = requests.get("http://169.254.169.254/latest/meta-data/placement/availability-zone", timeout=1)
            if response.status_code == 200:
                # remove AZ number from the end of the text
                return response.text[:-1]
        except Exception:
            pass

        # fallback to hardcoded in config region
        return self._config["region"]

    @property
    @lru_cache()
    def regions(self):
        """
        :return: list of AWS regions to check based on regions in main account or hardcoded list in config

        .. note:: auto detection of available AWS regions works only if "regions" key is not present in "aws" config section.
        """
        # for testing purposes allow regions overriding
        if "regions" in self._config:
            return self._config["regions"]
        # TODO: that is not the 100% right way to get regions,
        # as different accounts can have different regions available
        # with this code we will have list of regions available for main account
        ec2 = boto3.client('ec2')
        response = ec2.describe_regions()
        return [ region['RegionName'] for region in response['Regions'] ]

    @property
    def ddb_backup_retention(self):
        """ :return: number of days (timedelta) to retain DDB tables backup """
        return timedelta(days=self._config["ddb_backup"]["retention_days"])

    @property
    def ddb_backup_enabled(self):
        """ :return: boolean, if DDB backup should be performed """
        return self._config["ddb_backup"].get("enabled", True)


class ModuleConfig(BaseConfig):
    """ Base class for module configuration """
    def __init__(self, config, section):
        super().__init__(config, section)
        self._whitelist = config["whitelist"].get(section, {})
        self._fixnow = config["fixnow"].get(section, {})
        # main accounts dict
        self._accounts = config["aws"]["accounts"]
        self.name = section

    def module_accounts(self, option):
        """
        Each module can define its own list of accounts to identify/remediate.
        Account name (description) will be taken from main accounts dict,
        it means that each account in module list should have corresponding entry in main accounts dict.

        :return: dict with AWS accounts to identify/remediate {'account id': 'account name', ...}
        """
        module_accounts = self._config.get(option, None)
        if module_accounts is None:
            accounts = self._accounts
        else:
            # construct dict similar to main accounts dict
            accounts = {account: self._accounts.get(account, "") for account in module_accounts}
        # exclude 'ignore_accounts' from resulting dict
        return {k: v for k, v in accounts.items() if k not in self._config.get("ignore_accounts", [])}

    @property
    def accounts(self):
        """
        Each module can define its own list of accounts to identify in `accounts` option.

        :return: dict with AWS accounts to remediate {'account id': 'account name', ...}
        """
        return self.module_accounts(option="accounts")

    @property
    def remediation_accounts(self):
        """
        Each module can define its own list of accounts to remediate in `remediation_accounts` option.

        :return: dict with AWS accounts to remediate {'account id': 'account name', ...}
        """
        return self.module_accounts(option="remediation_accounts")

    @property
    def enabled(self):
        """ :return: boolean, if security issue check should be performed """
        return self._config.get("enabled", True)

    def in_fixnow(self, account_id, issue):
        """
        :param account_id: AWS account Id
        :param issue: Issue id

        :return: boolean, if issue Id in fixnow list
        """
        return issue in self._fixnow.get(account_id, [])

    def in_whitelist(self, account_id, issue):
        """
        :param account_id: AWS account Id
        :param issue: Issue id

        :return: boolean, if issue Id in whitelist
        """
        return issue in self._whitelist.get(account_id, [])

    @property
    def ddb_table_name(self):
        """ :return: DDB table name to use for storing issue details """
        return self._config["ddb.table_name"]

    @property
    def sns_topic_name(self):
        return self._config['topic_name']

    @property
    def reporting(self):
        """ :return: boolean, if reporting for issue should be enabled """
        return self._config.get("reporting", False)

    @property
    def remediation(self):
        """ :return: boolean, if remediation for issue should be enabled """
        return self._config.get("remediation", False)

    @property
    def remediation_retention_period(self):
        """ :return: int, number of days before performing auto remediation """
        return self._config.get("remediation_retention_period", 365)

    @property
    def issue_retention_date(self):
        """ :return: `timedelta` object before performing auto remediation """
        return timedelta(days=self.remediation_retention_period)


class IAMUserInactiveKeysConfig(ModuleConfig):
    """ Extend ModuleConfig with IAM inactive keys specific details """
    @property
    def inactive_criteria_days(self):
        """ :return: `timedelta` object to compare and mark access keys as inactive (not used for a long time) """
        return timedelta(days=int(self._config["inactive_criteria_days"]))


class IAMUserKeysRotationConfig(ModuleConfig):
    """ Extend ModuleConfig with IAM keys rotation specific details """
    @property
    def rotation_criteria_days(self):
        """ :return: `timedelta` object to compare and mark access keys as stale (created long time ago) """
        return timedelta(days=int(self._config["rotation_criteria_days"]))
