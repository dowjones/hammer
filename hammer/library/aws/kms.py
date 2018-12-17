import logging

from botocore.exceptions import ClientError

from library.aws import utility
from library.utility import jsonDumps


class KMSOperations:
    @classmethod
    def enable_key_rotation(cls, kms_client, key_id):
        """
        Enable rotation of given KMS key.

        :param kms_client: KMS boto3 client
        :param key_id: key Id to enable key rotation

        :return: nothing
        """
        kms_client.enable_key_rotation(KeyId=key_id)


class KMSKey(object):
    """
    Basic class for KMS key.
    Encapsulates access key Id, arn and rotation status.
    """
    def __init__(self, account, key_id, key_arn, tags, key_rotation_enabled):
        """
        :param account: Account
        :param key_id: KMS key id
        :param key_arn: KMS key arn
        :param key_rotation_enabled: KMS key rotation status is enabled or not
        """
        self.account = account
        self.id = key_id
        self.arn = key_arn
        self.tags = utility.convert_tags(tags)
        self.rotation_enabled = key_rotation_enabled

    def __str__(self):
        return (f"{self.__class__.__name__}("
                f"Id={self.id}, "
                f"Status={self.rotation_enabled}, "
                f")")

    def enable(self):
        """ Enable rotation of current KMS key """
        KMSOperations.enable_key_rotation(self.account.client("kms"), self.id)


class KMSKeyChecker(object):
    """
    Basic class for checking KMS key rotation details in account.
    Encapsulates check settings and discovered kms keys.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with KMS keys to check
        """
        self.account = account
        self.keys = []

    def get_key(self, key_id):
        """
        :return: `Key` by key id (name)
        """
        for key in self.keys:
            if key.id == key_id:
                return key
        return None

    def check(self, keys_to_check=None):
        """
        Walk through KMS keys in the account region and check them (rotation enabled/disabled).
        Put all gathered Keys to `self.keys`.

        :param keys_to_check: list with KMS kesy to check, if it is not supplied - all KMS keys must be checked

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # get all kms keys in account
            keys = self.account.client("kms").list_keys()['Keys']
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(kms:{err.operation_name})")
            else:
                logging.exception(f"Failed to list kms keys in {self.account}")
            return False

        logging.debug(f"Evaluating kms keys \n{jsonDumps(keys)}")
        for key_response in keys:
            key_id = key_response["KeyId"]
            key_arn = key_response["KeyArn"]

            if keys_to_check is not None and key_id not in keys_to_check:
                continue

            try:
                key_metadata = self.account.client("kms").describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(kms:{err.operation_name})")
                else:
                    logging.exception(f"Failed to get kms key metadata in {self.account} for key id: {key_id}")
                return False

            key_state = key_metadata["Enabled"]
            origin = key_metadata["Origin"]
            key_manager = key_metadata["KeyManager"]
            if origin == "AWS_KMS" and key_manager == "CUSTOMER" and key_state:
                try:
                    key_rotation_enabled = self.account.client("kms").get_key_rotation_status(
                        KeyId=key_id
                    )["KeyRotationEnabled"]
                except ClientError as err:
                    if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                        logging.error(f"Access denied in {self.account} "
                                      f"(kms:{err.operation_name})")
                    else:
                        logging.exception(f"Failed to get kms key rotation status in {self.account} for key id: {key_id}")
                    return False

                try:
                    tags = self.account.client("kms").list_resource_tags(KeyId=key_id).get("Tags", [])
                except ClientError as err:
                    if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                        logging.error(f"Access denied in {self.account} "
                                      f"(kms:{err.operation_name}, "
                                      f"resource='{key_id}')")
                    else:
                        logging.exception(f"Failed to get '{key_id}' tags in {self.account}")

                key = KMSKey(account=self.account, key_id=key_id, key_arn=key_arn, tags=tags,
                             key_rotation_enabled=key_rotation_enabled)
                self.keys.append(key)

        return True
