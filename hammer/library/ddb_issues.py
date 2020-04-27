import logging
import dateutil.parser


from operator import itemgetter
from enum import Enum
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime, timezone
from library.utility import jsonDumps


class IssueStatus(Enum):
    # used when no status field in DDB
    Unknown = "unknown"
    # set by identification - newly discovered issue or existing issue to reopen
    Open = "open"
    # set by identification - issue still exists but was added to whitelist
    Whitelisted = "whitelisted"
    # set by identification - issue was removed or remediated
    Resolved = "resolved"
    # set by reporting after closing ticket
    Closed = "closed"


class Details(object):
    """
    Base class to easy holding arbitrary values in DDB and be able to convert between dict in DDB and Python class.
    """
    def __init__(self, details):
        """
        :param details: dict with values to construct Details instance
        """
        self.__dict__['details'] = details

    def __setattr__(self, key, value):
        """ store any attribute in details dict """
        self.details[key] = value

    def __getattr__(self, item):
        """ get any attribute from details dict, defaulting to None """
        return self.details.get(item, None)

    def as_dict(self):
        """ return internal dict (Details class representation ready to insert into DDB) """
        return self.details


class Issue(object):
    """
    Base class for Hammer security issue. Python representation of DDB item.
    """
    def __init__(self, account_id, issue_id):
        # account id where issue was found (HASH key)
        self.account_id = account_id
        # issue id, must be uniq in account (RANGE key)
        self.issue_id = issue_id
        # current timestamp
        now = datetime.now(timezone.utc).isoformat()
        self.timestamps = Details({
            # issue was discovered
            "identified": now,
            # issue was updated (f.e. when open issue details were changed)
            "updated": now,
            # issue was reported
            "reported": None,
            # issue was remediated by hammer
            "remediated": None,
            # issue was closed (after remediation by user or hammer)
            "closed": None
        })
        # issue status
        self.status = IssueStatus.Open
        # issue specific details
        self.issue_details = Details({})
        # jira specific details
        self.jira_details = Details({})

    @property
    def timestamp_as_datetime(self):
        """
        Shows when Issue was reported

        :return: datatime object with Issue timestamp (tz aware)
        """
        return dateutil.parser.parse(self.timestamps.reported)

    def as_dict(self):
        """
        For storing Issue in DDB

        :return: dict, ready to store in DDB
        """
        return {
            'account_id': self.account_id,
            'issue_id': self.issue_id,
            'issue_details': self.issue_details.as_dict(),
            'status': self.status.value,
            'timestamps': self.timestamps.as_dict(),
            'jira_details': self.jira_details.as_dict(),
        }

    def as_string(self):
        """
        For comparison between Issues

        :return: string representation of Issue """
        items = self.as_dict()
        # remove elements related to reporting
        del items['timestamps']
        del items['jira_details']
        return jsonDumps(items, sort_keys=True)

    def __eq__(self, other):
        return self.as_string() == other.as_string()

    @staticmethod
    def from_dict(item, issue_class=None):
        """
        For converting data from DDB to Issue instance

        :param item: dict with issue details from DDB
        :param issue_class: Issue child class to construct instance from, if not set - parent class issue will be constructed
        """
        issue_class = Issue if issue_class is None else issue_class

        issue = issue_class(item['account_id'], item['issue_id'])
        issue.timestamps = Details(item['timestamps'])
        issue.status = IssueStatus(item.get('status', IssueStatus.Unknown))
        issue.issue_details = Details(item['issue_details'])
        issue.jira_details = Details(item['jira_details'])
        return issue

    def contains_tags(self, tags):
        if not tags:
            return True
        for k in tags:
            if k not in self.issue_details.tags:
                return False
            if self.issue_details.tags[k] not in tags[k]:
                return False
        return True


class SecurityGroupIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)
        # security group specific details about unrestricted permissions
        self.issue_details.perms = []

    def add_perm(self, protocol, from_port, to_port, cidr, status):
        self.issue_details.perms.append({
            'protocol': protocol,
            'from_port': from_port,
            'to_port': to_port,
            'cidr': cidr,
            'status': status.value,
        })
        # sort perms as sometimes IpPermissions are returned in mixed order
        self.issue_details.perms.sort(key=itemgetter('protocol', 'to_port', 'from_port', 'cidr', 'status'))

    def clear_perms(self):
        self.issue_details.perms.clear()


class CloudTrailIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)
        """ cloudtrails specific details about CloudTrails logging problems """
        self.issue_details.trails = []

    def add_trails(self, trails):
        for trail in trails:
            self.issue_details.trails.append({
                    'id': trail.id,
                    'enabled': trail.enabled,
                    'multi_region': trail.multi_region,
                    'selectors': trail.selectors,
                    'errors': trail.errors
            })
        # sort trails as sometimes trails are returned in mixed order
        self.issue_details.trails.sort(key=itemgetter('id'))

    def clear_trails(self):
        self.issue_details.trails.clear()


class RdsPublicSnapshotIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class S3PolicyIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class S3AclIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class EBSUnencryptedVolumeIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class EBSPublicSnapshotIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class IAMKeyRotationIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class IAMKeyInactiveIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)

class SQSPolicyIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class S3EncryptionIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class RdsEncryptionIssue(Issue):
    def __init__(self, *args):
        super().__init__(*args)


class PublicAMIIssue(Issue):
   def __init__(self, *args):
        super().__init__(*args)


class Operations(object):
    @staticmethod
    def find(ddb_table, issue):
        """
        Search for issue in DDB table

        :param ddb_table: boto3 DDB table resource to search in
        :param issue: Issue instance to search for (based on account id and issue id)

        :return: Issue instance based on item in DDB or None
        """
        response = ddb_table.get_item(
            Key={
                "account_id": issue.account_id,
                "issue_id": issue.issue_id
            }
        )
        if 'Item' in response:
            return Issue.from_dict(response['Item'])
        return None

    @classmethod
    def put(cls, ddb_table, issue):
        """
        Safely puts `issue` to `ddb_table` as is

        :param ddb_table: boto3 DDB table resource to replace in
        :param issue: Issue instance to update

        :return: nothing
        """
        try:
            ddb_table.put_item(Item=issue.as_dict())
        except Exception as err:
            logging.error(f"Failed to put issue to '{ddb_table}'\n{jsonDumps(issue.as_dict())}\n{err}")
        else:
            logging.debug(f"Updated {issue.account_id}/{issue.issue_id} issue")

    @classmethod
    def update(cls, ddb_table, issue):
        """
        Merges issue in DDB with provided issue (if necessary).

        :param ddb_table: boto3 DDB table resource to replace in
        :param issue: Issue instance

        :return: nothing
        """
        logging.debug(f"Checking DDB '{ddb_table.name}' for {issue.account_id}/{issue.issue_id}")
        issue_from_db = cls.find(ddb_table, issue)
        if issue_from_db is None:
            # issue does not exist in DDB - create new record
            cls.put(ddb_table, issue)
            return

        # issue exists in DDB, need to check issue details
        if issue == issue_from_db:
            logging.debug(f"{issue.account_id}/{issue.issue_id} no changes since last run, skipping")
        elif issue.status == IssueStatus.Whitelisted and issue_from_db.status == IssueStatus.Closed:
            logging.debug(f"{issue.account_id}/{issue.issue_id} no need to reopen whitelisted issue, skipping")
        else:
            if issue_from_db.status == IssueStatus.Closed:
                logging.debug("Existing closed issue was changed, abandon jira details and timestamps")
            else:
                logging.debug(f"Existing not closed issue was changed, preserving jira details and timestamps:\n"
                              f"{issue_from_db.as_string()}\n"
                              f"{issue.as_string()}")
                issue.timestamps = issue_from_db.timestamps
                issue.timestamps.updated = datetime.now(timezone.utc).isoformat()
                issue.jira_details = issue_from_db.jira_details
            cls.put(ddb_table, issue)

    @staticmethod
    def get_account_open_issues(ddb_table, account_id, issue_class=None):
        """
        Search for account open issues. Search uses filter expressions - may be not efficient enough.

        :param ddb_table: boto3 DDB table resource to search in
        :param account_id: AWS account id to search issues for
        :param issue_class: one of Issue class children (issue type to construct)

        :return: all account open issue
        """
        issues = []
        first_iteration = True
        response = None
        while first_iteration == True or 'LastEvaluatedKey' in response:
            response = ddb_table.query(KeyConditionExpression=Key('account_id').eq(account_id),
                                    FilterExpression=Attr('status').eq(IssueStatus.Open.value))
            for item in response['Items']:
                issues.append(Issue.from_dict(item, issue_class))

            if first_iteration == True:
                first_iteration = False
        return issues

    @staticmethod
    def get_account_closed_issues(ddb_table, account_id, issue_class=None):
        """
        Search for account closed issues. Search uses filter expressions - may be not efficient enough.

        :param ddb_table: boto3 DDB table resource to search in
        :param account_id: AWS account id to search issues for
        :param issue_class: one of Issue class children (issue type to construct)

        :return: all account closed issue
        """
        issues = []
        response = ddb_table.query(KeyConditionExpression=Key('account_id').eq(account_id),
                                   FilterExpression=Attr('status').eq(IssueStatus.Closed.value))
        for item in response['Items']:
            issues.append(Issue.from_dict(item, issue_class))
        return issues

    @staticmethod
    def get_account_not_closed_issues(ddb_table, account_id, issue_class=None):
        """
        Search for account not closed issues (open, whitelisted, resolved, ...).
        Search uses filter expressions - may be not efficient enough.

        :param ddb_table: boto3 DDB table resource to search in
        :param account_id: AWS account id to search issues for
        :param issue_class: one of Issue class children (issue type to construct)

        :return: all account not closed issue
        """
        issues = []
        response = ddb_table.query(KeyConditionExpression=Key('account_id').eq(account_id),
                                   FilterExpression=Attr('status').ne(IssueStatus.Closed.value))
        for item in response['Items']:
            issues.append(Issue.from_dict(item, issue_class))
        return issues

    @classmethod
    def set_status_closed(cls, ddb_table, issue):
        """
        Put issue with closed status and updated closed timestamp

        :param ddb_table: boto3 DDB table resource
        :param issue: Issue instance

        :return: nothing
        """
        issue.timestamps.closed = datetime.now(timezone.utc).isoformat()
        issue.status = IssueStatus.Closed
        cls.put(ddb_table, issue)

    @classmethod
    def set_status_resolved(cls, ddb_table, issue):
        """
        Put issue with resolved status and updated resolved timestamp

        :param ddb_table: boto3 DDB table resource
        :param issue: Issue instance

        :return: nothing
        """
        issue.timestamps.resolved = datetime.now(timezone.utc).isoformat()
        issue.status = IssueStatus.Resolved
        cls.put(ddb_table, issue)

    @classmethod
    def set_status_remediated(cls, ddb_table, issue):
        """
        Put issue with updated remediated timestamp

        :param ddb_table: boto3 DDB table resource
        :param issue: Issue instance

        :return: nothing
        """
        issue.timestamps.remediated = datetime.now(timezone.utc).isoformat()
        cls.put(ddb_table, issue)

    @classmethod
    def set_status_reported(cls, ddb_table, issue):
        """
        Put issue with updated reported timestamp

        :param ddb_table: boto3 DDB table resource
        :param issue: Issue instance

        :return: nothing
        """
        issue.timestamps.reported = datetime.now(timezone.utc).isoformat()
        cls.put(ddb_table, issue)

    @classmethod
    def set_status_updated(cls, ddb_table, issue):
        """
        Put issue with updated updated timestamp

        :param ddb_table: boto3 DDB table resource
        :param issue: Issue instance

        :return: nothing
        """
        issue.timestamps.updated = issue.timestamps.reported
        cls.put(ddb_table, issue)
