import logging
import os


from io import BytesIO
from functools import lru_cache
from slackclient import SlackClient
from library.config import Config


class SlackNotification(object):
    def __init__(self, config=None):
        self.config = Config() if config is None else config
        self.sc = SlackClient(self.config.slack.api_token)
        self.slackUser = "hammer"

    @property
    @lru_cache(maxsize=1)
    def users(self):
        """
        Get and cache list of slack users

        :return: dict with slack users by name and email
        """
        users = {}
        response = self.sc.api_call("users.list")
        if response.get("ok"):
            for member in response["members"]:
                id = member.get("id", None)
                name = member.get("name", None)
                email = member.get("profile", {}).get("email", None)
                if id is not None:
                    if name is not None:
                        users[name.lower()] = id
                    if email is not None:
                        users[email.lower()] = id
        return users

    def user_id(self, user):
        """
        Search for slack user id by name/email

        :param user: string with user name of email

        :return: string with slack user id
        """
        return self.users.get(user.lower(), None)

    def post_message(self, msg, owner=None):
        if not self.config.slack.enabled:
            return

        # if owner is not set - try to find channel to send msg to based on msg body
        owner = owner if owner is not None else self.config.slack.find_channel(msg)
        # open user channel if owner is not prefixed with #
        channel = owner if owner.startswith("#") else self.open_user_channel(owner)

        if not channel:
            logging.debug(f"ignoring: '{msg}'")
            return

        logging.debug(f"sending to '{owner}': {msg}")
        try:
            response = self.sc.api_call("chat.postMessage",
                                        channel=channel,
                                        username=self.slackUser,
                                        text=msg
                                       )
            if not response.get("ok"):
                logging.error(f"Failed to send slack message: {response.get('error')}\n{response}")
        except Exception:
            logging.exception(f"Failed to send slack message to {owner}\n{msg}")

    @lru_cache()
    def open_user_channel(self, user):
        # check if user exists in slack and get its id
        user_id = self.user_id(user)
        if user_id is None:
            return None

        response = self.sc.api_call(
            "im.open",
            user=user_id
        )
        if not response.get("ok"):
            logging.error(f"Failed to open channel to '{user}' (id={user_id}): {response['error']}")
            return None

        return response["channel"]["id"]

    def send_snippet(self, content, channel, content_type="text"):
        response = self.sc.api_call(
            "files.upload",
            channels=channel,
            content=content,
            filetype=content_type,
            username=self.slackUser
        )
        if not response.get("ok"):
            logging.error(f"Failed to send slack snippet: {response.get('error')}\n{response}")

    def send_file(self, file_name, file_data, channel):
        file_type = os.path.splitext(file_name)[1]

        if isinstance(file_data, BytesIO):
            file_data.seek(0)

        response = self.sc.api_call(
            "files.upload",
            channels=channel,
            filename=file_name,
            file=file_data,
            filetype=file_type,
            username=self.slackUser
        )
        if not response.get("ok"):
            logging.error(f"Failed to send slack file: {response.get('error')}\n{response}")
    
    def send_file_notification(self, file_name, file_data, channel=None, user_mail=None):
        if channel is None:
            if not user_mail:
                return

            channel = self.open_user_channel(user_mail)

        self.send_file(file_name, file_data, channel)

    def report_issue(self, msg,
                     owner=None,
                     account_id=None,
                     bu=None, product=None,
                     ):
        try:
            # notify default owner as well if set in config
            owners = self.config.owners.slack_owner() if self.config.slack.notify_default_owner else []

            owners += self.config.owners.slack_owner(
                account=account_id,
                bu=bu, product=product,
            )

            # use provided owner as well if it is a channel or valid slack user
            if owner is not None and \
               (owner.startswith("#") or self.user_id(owner) is not None):
                owners.append(owner)

            # iterate over set to exclude duplicates
            for owner in set(owners):
                self.post_message(msg, owner)
        except Exception:
            logging.exception("Failed to report issue to Slack")
