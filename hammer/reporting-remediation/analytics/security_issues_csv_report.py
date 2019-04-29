import logging
import xlwt
import sys


from io import BytesIO
from library.logger import set_logging, add_cw_logging
from library.aws.utility import AssumeRole
from library.config import Config
from library.ddb_issues import Operations as IssueOperations
from library.ddb_issues import SecurityGroupIssue, S3AclIssue, S3PolicyIssue, CloudTrailIssue, IAMKeyRotationIssue, IAMKeyInactiveIssue, RdsPublicSnapshotIssue, EBSUnencryptedVolumeIssue, EBSPublicSnapshotIssue, SQSPolicyIssue
from analytics.add_excel_sheet_records import AddRecordsToSheet
from library.slack_utility import SlackNotification
from library.aws.s3 import S3Operations
from datetime import datetime, timezone


class CSVReport(object):
    def __init__(self):
        self.config = Config()

    def add_open_issues_to_sheet(self, ddb_table, work_book, sheet_name, issue_class):
        worksheet = work_book.add_sheet(sheet_name)
        # Adding Headers to Execl sheet with DynamoDB table field names.
        AddRecordsToSheet.add_header_data(worksheet, sheet_name)
        row_number = 0
        for account_id, account_name in self.config.aws.accounts.items():
            issues = IssueOperations.get_account_open_issues(ddb_table, account_id, issue_class)

            for issue in issues:
                # updated_date = dateutil.parser.parse(issue.timestamps.updated)
                # no_of_days_issue_created = (self.config.now - updated_date).days
                # if no_of_days_issue_created <= 7:
                row_number = row_number + 1
                # Adding row data to Execl sheet with DynamoDB table field values.
                AddRecordsToSheet.add_records(worksheet, sheet_name, account_id, account_name, issue, row_number)
                # for remediation to work issue must be reported,
                # so if no other reporting available - set issue is reported here
                if issue.timestamps.reported is None and \
                   (not self.config.jira.enabled) and \
                   (not self.config.slack.enabled):
                    IssueOperations.set_status_reported(ddb_table, issue)

    def add_closed_issues_to_sheet(self, ddb_table, work_book, sheet_name, issue_class):
        worksheet = work_book.add_sheet(sheet_name)
        # Adding Headers to Execl sheet with DynamoDB table field names.
        AddRecordsToSheet.add_header_data(worksheet, sheet_name)
        row_number = 0
        for account_id, account_name in self.config.aws.accounts.items():
            issues = IssueOperations.get_account_closed_issues(ddb_table, account_id, issue_class)

            for issue in issues:
                updated_date = issue.timestamp_as_datetime
                no_of_days_issue_closed = (self.config.now - updated_date).days
                if no_of_days_issue_closed <= 7:
                    row_number = row_number + 1
                    # Adding row data to Execl sheet with DynamoDB table field values.
                    AddRecordsToSheet.add_records(worksheet, sheet_name, account_id, account_name, issue, row_number)

    def generate(self):
        main_account_session = AssumeRole.get_session(region=self.config.aws.region)
        issues = [
            (self.config.sg.ddb_table_name, "Insecure Services", SecurityGroupIssue),
            (self.config.s3acl.ddb_table_name, "S3 ACL Public Access", S3AclIssue),
            (self.config.s3policy.ddb_table_name, "S3 Policy Public Access", S3PolicyIssue),
            (self.config.iamUserInactiveKeys.ddb_table_name, "IAM User Inactive Keys", IAMKeyInactiveIssue),
            (self.config.iamUserKeysRotation.ddb_table_name, "IAM User Key Rotation", IAMKeyRotationIssue),
            (self.config.ebsVolume.ddb_table_name, "EBS Unencrypted Volumes", EBSUnencryptedVolumeIssue),
            (self.config.ebsSnapshot.ddb_table_name, "EBS Public Snapshots", EBSPublicSnapshotIssue),
            (self.config.cloudtrails.ddb_table_name, "CloudTrail Logging Issues", CloudTrailIssue),
            (self.config.rdsSnapshot.ddb_table_name, "RDS Public Snapshots", RdsPublicSnapshotIssue),
            (self.config.sqspolicy.ddb_table_name, "SQS Policy Public Access", SQSPolicyIssue),
        ]

        open_security_issues_workbook = xlwt.Workbook()
        closed_security_issues_workbook = xlwt.Workbook()

        for table_name, sheet_name, issueType in issues:
            logging.debug(f"Building {issueType.__name__} report")
            ddb_table = main_account_session.resource("dynamodb").Table(table_name)
            self.add_open_issues_to_sheet(ddb_table, open_security_issues_workbook, sheet_name, issueType)
            self.add_closed_issues_to_sheet(ddb_table, closed_security_issues_workbook, sheet_name, issueType)

        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')

        open_security_issues = BytesIO()
        open_security_issues_file_name = f"open_security_issues_{timestamp}.xls"
        closed_security_issues = BytesIO()
        closed_security_issues_file_name = f"security_issues_closed_last_week_{timestamp}.xls"

        open_security_issues_workbook.save(open_security_issues)
        closed_security_issues_workbook.save(closed_security_issues)

        if self.config.csv.bucket:
            open_security_issues_path = f"reports/{open_security_issues_file_name}"
            closed_security_issues_path = f"reports/{closed_security_issues_file_name}"

            logging.debug(f"Uploading CSV report to s3://{self.config.csv.bucket}/{open_security_issues_path}")
            S3Operations.put_object(
                main_account_session.client("s3"),
                self.config.csv.bucket,
                open_security_issues_path,
                open_security_issues
            )

            logging.debug(f"Uploading CSV report to s://{self.config.csv.bucket}/{closed_security_issues_path}")
            S3Operations.put_object(
                main_account_session.client("s3"),
                self.config.csv.bucket,
                closed_security_issues_path,
                closed_security_issues
            )

        if self.config.slack.enabled:
            channel = self.config.csv.slack_channel
            slack_obj = SlackNotification(config=self.config)
            logging.debug(f"Uploading CSV report to slack ({channel})")
            slack_obj.send_file_notification(
                file_name=open_security_issues_file_name,
                file_data=open_security_issues,
                channel=channel)
            slack_obj.send_file_notification(
                file_name=closed_security_issues_file_name,
                file_data=closed_security_issues,
                channel=channel)



if __name__ == '__main__':
    module_name = sys.modules[__name__].__loader__.name
    set_logging(level=logging.DEBUG, logfile=f"/var/log/hammer/{module_name}.log")
    config = Config()
    add_cw_logging(config.local.log_group,
                   log_stream=module_name,
                   level=logging.DEBUG,
                   region=config.aws.region)
    try:
        obj = CSVReport()
        obj.generate()
    except Exception:
        logging.exception("Failed to generate security issues report")
