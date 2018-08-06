import json
import re


from slackbot.bot import respond_to
from slackbot.settings import config


@respond_to('^ping$', re.IGNORECASE)
def ping(message):
    """ bot availability check """
    message.reply('pong!')


@respond_to('^accounts$', re.IGNORECASE)
@respond_to('^accounts (?P<substr>.*)$', re.IGNORECASE)
def accounts(message, substr=None):
    """ shows list of configured accounts with *substr* in name. *substr* can be omited to get the list with all configured accounts """
    if substr is not None: substr = substr.lower()

    response = "\n"
    for account_id, account_name in config.aws.accounts.items():
        if substr is None or substr in account_name.lower():
            response += f"{account_id}\t{account_name}\n"
    if response:
        filename = "accounts.txt" if substr is None else f"accounts_{substr}.txt"
        message.channel.upload_content(filename, response)
    else:
        message.reply("no accounts have been found")


@respond_to('^account (?P<account_num>.*) name$', re.IGNORECASE)
def account_name(message, account_num):
    """ shows account name by account number """
    title = config.aws.accounts.get(account_num)
    message.reply(f"`{account_num}` account name is " + (f"`{title}`" if title else "unknown"))


@respond_to('^account (?P<account_num>.*) status$', re.IGNORECASE)
def account_status(message, account_num):
    """ shows modules status for *account_num* account """
    if account_num not in config.aws.accounts:
        message.reply(f"`{account_num}` is not configured")
        return

    response = f"`{account_num} ({config.aws.accounts[account_num]})` status:\n"
    for module in config.modules:
        if account_num not in module.accounts:
            continue
        response += f"• *{module.section}*\t"
        if module.enabled:
            response += f"`identification`"
            if module.reporting:
                response += ", `reporting`"
            if module.remediation:
                response += ", `remediation`"
        else:
            response += f"`disabled`"
        response += "\n"
    message.reply(response)


@respond_to('^status$', re.IGNORECASE)
def status(message):
    """ shows global modules status """
    response = "\n"
    for module in config.modules:
        response += f"• *{module.section}*\t"
        if module.enabled:
            response += f"`identification`"
            if config.aws.accounts != module.accounts:
                response += " ["
                response += ", ".join([f"{num} ({name})" for num, name in module.accounts.items()])
                response += "]"
            if module.reporting:
                response += ", `reporting`"
            if module.remediation:
                response += ", `remediation`"
        else:
            response += f"`disabled`"
        response += "\n"
    message.reply(response)


@respond_to('^(?P<section>.*) config$', re.IGNORECASE)
def section_config(message, section):
    """ shows *section* module config """
    response = "```"
    for module in config.modules:
        if module.section == section:
            response += json.dumps(module._config, indent=4)
    response += "```"
    message.reply(response)


@respond_to('^(?P<term>.*) whitelisted items$', re.IGNORECASE)
def whitelisted(message, term):
    """ shows *module* or *account* whitelisted items """
    sections = [ module.section for module in config.modules ]
    response = "\n"
    if term in sections:
        section = term
        for module in config.modules:
            if module.section == section:
                for account_num, items in module._whitelist.items():
                    if account_num not in config.aws.accounts:
                        # skip __comment__ and stale accounts
                        continue
                    response += f"• *{account_num} ({config.aws.accounts[account_num]})*\t"
                    response += "["
                    response += ", ".join(items)
                    response += "]\n"
                break
    elif term in config.aws.accounts:
        account_num = term
        for module in config.modules:
            if account_num in module._whitelist:
                response += f"• *{module.section}*\t["
                response += ", ".join(module._whitelist[account_num])
                response += "]\n"
    else:
        message.reply("no items have been found")
        return

    message.reply(response)
