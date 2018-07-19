import logging


from botocore.exceptions import ClientError
from datetime import datetime, timezone
from library.logger import set_logging
from library.config import Config
from library.aws.utility import Account


class DDBackuper(object):
    """
    TODO: this should be replaced with DynamoDB Point-in-Time recovery when CloudFormattion will support it.
    """
    def __init__(self):
        self.config = Config()
        self.enabled = self.config.aws.ddb_backup_enabled
        self.retention_period = self.config.aws.ddb_backup_retention
        self.account = Account(region=self.config.aws.region)
        self.ddb_client = self.account.client('dynamodb')
        self.ddb_resource = self.account.resource('dynamodb')
        self.now = datetime.now(timezone.utc)
        # used as a part of backup name
        self.today = self.now.strftime("%Y-%m-%d")

    def filter_tables(self):
        """ Return list of hammer ddb tables with existing backups """
        hammer_tables = {}

        for module in self.config.modules:
            table_name = module.ddb_table_name
            try:
                hammer_tables[table_name] = self.ddb_client.list_backups(
                    TableName=table_name
                )['BackupSummaries']
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"({self.ddb_client.__class__.__name__.lower()}:{err.operation_name})")
                else:
                    logging.exception(f"Failed to list '{table_name}' backups in {self.account}")
                continue
        return hammer_tables

    def today_backup_name(self, table_name):
        return f"{table_name}_{self.today}"

    def today_backup_exists(self, table_name, backups):
        """ Returns if today's backup exists in provided list of backups
            Check is based on backup name and self.today
        """
        return self.today_backup_name(table_name) in [ backup['BackupName'] for backup in backups ]

    def check_backups(self, table_name, backups):
        """ Log error if any backup status for provided list of backups is not AVAILABLE """
        for backup in backups:
            name = backup["BackupName"]
            status = backup["BackupStatus"]
            if status != "AVAILABLE":
                logging.error(f"{table_name} backup is not available: {name}")

    def launch_backup(self, table_name):
        try:
            self.ddb_client.create_backup(
                TableName=table_name,
                BackupName=self.today_backup_name(table_name)
            )
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"({self.ddb_client.__class__.__name__.lower()}:{err.operation_name})")
            else:
                logging.exception(f"Failed to create '{table_name}' backup in {self.account}")
            return False
        return True

    def rotate_backups(self, table_name, backups):
        """ Removes all outdated backups from provided list of backups
            Check is based on backup creation date and retention period from config
        """
        for backup in backups:
            creationDate = backup['BackupCreationDateTime']
            name = backup['BackupName']
            arn = backup['BackupArn']
            if self.now - creationDate > self.retention_period:
                logging.debug(f"Deleting outdated backup '{name}' for '{table_name}' ({arn})")
                try:
                    self.ddb_client.delete_backup(BackupArn=arn)
                except ClientError as err:
                    if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                        logging.error(f"Access denied in {self.account} "
                                      f"({self.ddb_client.__class__.__name__.lower()}:{err.operation_name})")
                    else:
                        logging.exception(f"Failed to delete '{arn}' backup in {self.account}")

    def run(self):
        if not self.enabled:
            logging.debug("DDB backup disabled")
            return
        for table_name, backups in self.filter_tables().items():
            self.check_backups(table_name, backups)
            if not self.today_backup_exists(table_name, backups):
                logging.debug(f"Launching backup of {table_name}")
                if self.launch_backup(table_name):
                    self.rotate_backups(table_name, backups)
            else:
                logging.warning(f"Today backup exists for {table_name}, skipping")

def lambda_handler(event, context):
    set_logging(level=logging.DEBUG)

    try:
        backuper = DDBackuper()
        backuper.run()
    except Exception:
        logging.exception(f"Failed to backup DDB tables")
        return


if __name__ == '__main__':
    lambda_handler(None, None)