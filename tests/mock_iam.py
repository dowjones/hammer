import boto3
import moto
import logging

from moto import mock_iam
from moto.iam.models import iam_backend
from moto.iam.exceptions import IAMNotFoundException
from datetime import datetime
from library.utility import jsonDumps


def find_key_prop(users, key, prop, default):
    for test_key in users[key.user.id]["Keys"]:
        if test_key["Id"] == key.id:
            return test_key[prop]
    return default


def start():
    """
    Entrypoint for mocking IAM.
    :return: nothing
    """
    # start IAM mocking with moto
    mock = mock_iam()
    mock.start()
    """ Monkey-patching of moto """
    # create new field in AccessKey model for LastUsedDate attribute
    moto.iam.models.AccessKey.last_used = None
    # create hook for GetAccessKeyLastUsed API call
    moto.iam.responses.IamResponse.get_access_key_last_used = get_access_key_last_used
    """ Monkey-patching is done """


def create_env(users):
    logging.debug(f"======> creating new IAM env for {jsonDumps(users)}")
    iam_client = boto3.client("iam")

    for username in users:
        iam_client.create_user(UserName=username)
        for indx, key in enumerate(users[username]["Keys"]):
            newkey = iam_client.create_access_key(UserName=username)
            # update key 'users' with 'Id' of newly created key (for test to find "CheckShouldPass")
            key["Id"] = newkey['AccessKey']['AccessKeyId']
            # update key 'users' with index of newly created key (for easy recognition of failed tests)
            key["TestId"] = indx + 1
            iam_client.update_access_key(UserName=username,
                                         AccessKeyId=key["Id"],
                                         Status="Active" if key["Active"] else "Inactive")
            if key.get("LastUsed", None):
                user_update_key_last_used(username, key["Id"], key["LastUsed"])
            if key.get("CreateDate", None):
                user_update_key_create_date(username, key["Id"], key["CreateDate"])


def get_access_key_last_used(self):
    """
    Hook function for GetAccessKeyLastUsed API call
    """
    access_key_id = self._get_param('AccessKeyId')
    users = iam_backend.list_users(None, None, None)
    user_name = None
    for user in users:
        keys = user.get_all_access_keys()
        for key in keys:
            if access_key_id == key.access_key_id:
                user_name = user.name
                last_used = key.last_used.isoformat() if key.last_used else key.last_used
                break
    if not user_name:
        raise IAMNotFoundException("AccessKeyId {0} not found".format(access_key_id))

    template = self.response_template(GET_ALL_ACCESS_KEYS_TEMPLATE)
    return template.render(user_name=user_name, last_used=last_used)


def user_update_key_last_used(user, keyid, timestamp):
    """
    Allows to change LastUsedDate in moto IAM backend.

    :param user: string with user name
    :param keyid: string with keyId
    :param timestamp: datetime object with desired value for LastUsedDate
    :return: nothing, raises IAMNotFoundException if user/keyId was not found
    """
    for idx, key in enumerate(iam_backend.users[user].access_keys):
        if key.access_key_id == keyid:
            iam_backend.users[user].access_keys[idx].last_used = timestamp
            break
    else:
        raise IAMNotFoundException("AccessKeyId {0} not found".format(keyid))


def user_update_key_create_date(user, keyid, timestamp):
    """
    Allows to change CreateDate in moto IAM backend.

    :param user: string with user name
    :param keyid: string with keyId
    :param timestamp: datetime object with desired value for CreateDate
    :return: nothing, raises IAMNotFoundException if user/keyId was not found
    """
    for idx, key in enumerate(iam_backend.users[user].access_keys):
        if key.access_key_id == keyid:
            iam_backend.users[user].access_keys[idx].create_date = datetime.strftime(
                timestamp,
                "%Y-%m-%dT%H:%M:%SZ"
            )
            break
    else:
        raise IAMNotFoundException("AccessKeyId {0} not found".format(keyid))


# XML response template for GetAccessKeyLastUsed API call
GET_ALL_ACCESS_KEYS_TEMPLATE = """<GetAccessKeyLastUsedResponse>
  <GetAccessKeyLastUsedResult>
     <AccessKeyLastUsed>
       {% if last_used %}
       <Region>us-west-2</Region>
       <LastUsedDate>{{ last_used }}</LastUsedDate>
       <ServiceName>s3</ServiceName>
       {% else %}
       <Region>N/A</Region>
       <ServiceName>N/A</ServiceName>
       {% endif %}
     </AccessKeyLastUsed>
     <UserName>{{ user_name }}</UserName>
  </GetAccessKeyLastUsedResult>
  <ResponseMetadata>
     <RequestId>7a62c49f-347e-4fc4-9331-6e8eEXAMPLE</RequestId>
  </ResponseMetadata>
</GetAccessKeyLastUsedResponse>"""
