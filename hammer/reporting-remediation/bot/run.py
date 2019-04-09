import logging
import sys


from library.logger import set_logging, add_cw_logging
from library.config import Config
from slackbot.dispatcher import MessageDispatcher
from slackbot import settings
from slackbot.bot import Bot


class MessageDispatcherExt(MessageDispatcher):
    def filter_text(self, msg):
        full_text = msg.get('text', '') or ''
        channel = msg['channel']
        bot_name = self._get_bot_name()
        bot_id = self._get_bot_id()
        m = self.AT_MESSAGE_MATCHER.match(full_text)

        if channel[0] == 'C' or channel[0] == 'G':
            if not m:
                return

            matches = m.groupdict()

            atuser = matches.get('atuser')
            username = matches.get('username')
            text = matches.get('text')
            alias = matches.get('alias')

            if alias:
                atuser = bot_id

            if atuser != bot_id and username != bot_name:
                # a channel message at other user
                return
            msg['text'] = text
        else:
            if m:
                msg['text'] = m.groupdict().get('text', None)
            else:
                # if this is threaded conversation inside direct channel, it will be treated as "listen_to" category
                if msg.get('thread_ts', None):
                    return
        return msg


def main():
    bot = Bot()
    # find out a way to reuse slackbot package without usage of protected variables
    bot._dispatcher = MessageDispatcherExt(bot._client, bot._plugins, settings.ERRORS_TO)
    bot.run()


if __name__ == "__main__":
    module_name = sys.modules[__name__].__loader__.name
    set_logging(level=logging.WARNING, logfile=f"/var/log/hammer/{module_name}.log")
    settings.config = Config()
    if not settings.config.slack.enabled:
        sys.exit(0)

    settings.API_TOKEN = settings.config.slack.api_token
    settings.PLUGINS = ['bot.commands']
    add_cw_logging(settings.config.local.log_group,
                   log_stream=module_name,
                   level=logging.WARNING,
                   region=settings.config.aws.region)
    main()
