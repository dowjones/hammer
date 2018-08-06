import logging
import sys


from library.logger import set_logging, add_cw_logging
from library.config import Config
from slackbot import settings
from slackbot.bot import Bot


def main():
    bot = Bot()
    bot.run()


if __name__ == "__main__":
    module_name = sys.modules[__name__].__loader__.name
    set_logging(level=logging.WARNING, logfile=f"/var/log/hammer/{module_name}.log")
    settings.config = Config()
    settings.API_TOKEN = settings.config.slack.api_token
    settings.PLUGINS = ['bot.commands']
    add_cw_logging(settings.config.local.log_group,
                   log_stream=module_name,
                   level=logging.WARNING,
                   region=settings.config.aws.region)
    main()
