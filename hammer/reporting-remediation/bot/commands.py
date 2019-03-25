import json
import re
import requests
import time


from slackbot.bot import listen_to, respond_to
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


message_mapping = {
    's3_bucket_policy': '*These buckets have public policy:* ',
    's3_bucket_acl': '*These buckets contain public ACLs:* ',
    's3_encryption': '*These buckets are unencrypted:* ',
    'user_inactivekeys': '*Users with inactive keys:* ',
    'user_keysrotation': '*Users with keys to rotate:* ',
    'secgrp_unrestricted_access': '*These security groups are open to outside world:*  \n',
    'cloudtrails': '*These trails are disabled or contain delivery errors:* ',
    'ebs_unencrypted_volume': '*These EBS volumes are unencrypted:* ',
    'ebs_public_snapshot': '*These EBS snapshots are public:* ',
    'rds_public_snapshot': '*These RDS snapshots are public:* ',
    'sqs_public_access': '*These SQS are publicly accessible:* ',
    'rds_encryption': '*These RDS instances are unencrypted:* '
}


def format_scan_account_result(scan_result):
    result = ""
    for region in scan_result:
        if not any(v for k, v in scan_result[region].items()):
            continue
        result += f"*Found these issues in {region} region:* \n"
        for sec_feature in scan_result[region]:
            if scan_result[region][sec_feature]:
                if sec_feature == 'secgrp_unrestricted_access':
                    result += message_mapping[sec_feature]
                    for issue in scan_result[region][sec_feature]:
                        open_ports = ''
                        for open_ports_info in issue['issue_details']['perms']:
                            to_port = open_ports_info['to_port'] if open_ports_info['to_port'] else 'All'
                            protocol = open_ports_info['protocol'] if open_ports_info['protocol'] != '-1' else 'All'
                            open_ports += f"port {to_port}, " \
                                f"protocol: {protocol}, " \
                                f"cidr: {open_ports_info['cidr']}; "
                        result += f"Security group id: {issue['id']}, Open ports: {open_ports}\n"
                    continue
                result += message_mapping[sec_feature]
                issues_id = [issue['id'] for issue in scan_result[region][sec_feature]]
                issues = ','.join(issues_id)
                result += '[' + issues + ']\n'
    if not result:
        return 'No vulnerabilities found. Congrats!'
    return result


def scan_account(message, account_num, regions, security_features, tags):
    api_token = config.api.token
    api_url = config.api.url + '/identify'
    headers = {'Auth': api_token}
    request_body = {
        'account_id': account_num,
        'regions': regions,
        'security_features': security_features,
        'tags': tags
    }
    resp = requests.post(api_url, json=request_body, headers=headers)
    if resp.status_code != 200:
        message.reply(f'Failed to start scan for account {account_num}, {resp.text}')
        return
    message.reply(f'Scan for account {account_num} has been started. When the scan is finished,'
                  f'you will be notified with results.')
    request_id = resp.json()['request_id']
    time_start = time.time()
    while time.time() - time_start < 300:
        resp = requests.get(api_url + '/' + request_id, headers=headers)
        if resp.json()['scan_status'] == 'COMPLETE':
            message.reply(format_scan_account_result(resp.json()['scan_results']))
            return
        if resp.json()['scan_status'] == 'FAILED':
            return message.reply(f'Scan of account {account_num} is failed. Please try again later.')
        time.sleep(5)
    return message.reply('Sorry, but current scan takes too long to finish.')


QUESTION_1 = '''
Please specify regions which you want to scan. Use comma as a separator between region values.
Specify `all` if you want to scan all regions. Allowed values: \n ```%s```'''

QUESTION_2 = '''
Please specify security features you want to check. Use comma as a separator between values.
Specify `all` if you want to check every supported resource. Allowed values: \n ```%s```
'''

QUESTION_3 = '''
Please specify tags. The tags should be valid json. Specify `{}` if you want to scan all resources.
Example: `{"bu": ["mybu1", "mybu2"], "owner": ["owner1", "owner2"]}`.
'''


def parse_regions(response):
    regions = []
    supported_regions = config.aws.regions
    allowed_values = '\n'.join(supported_regions)
    requested_regions = response.split(',')
    if 'all' in requested_regions and len(requested_regions) == 1:
        return regions
    for region in requested_regions:
        if region.strip() not in supported_regions:
            raise Exception(f'Wrong region {region}. Allowed values: \n ```{allowed_values}```')
        else:
            regions.append(region.strip())
    return regions


def parse_security_features(response):
    security_features = []
    supported_features = [module.section for module in config.modules]
    allowed_values = '\n'.join(supported_features)
    requested_security_features = response.split(',')
    if 'all' in requested_security_features and len(requested_security_features) == 1:
        return []
    for sec_feature in requested_security_features:
        if sec_feature.strip() not in supported_features:
            raise Exception(f"Unsupported security feature {sec_feature}. Allowed values: \n ```{allowed_values}```")
        else:
            security_features.append(sec_feature.strip())
    return security_features


def parse_tags(response):
    try:
        return json.loads(response)
    except Exception:
        raise Exception('Can not parse tags. Please specify tags in the following format: '
                        '`{"tag_name": ["value1", "value2"]}`')


def parse_answer(message, user_response, thread_ts):
    current_question = get_current_question(thread_ts)
    DIALOGS[thread_ts]['answers'].append(QUESTIONS[current_question]['parse_func'](user_response))
    if len(DIALOGS[thread_ts]['answers']) == len(QUESTIONS):
        scan_account(message, DIALOGS[thread_ts]['account'], *DIALOGS[thread_ts]['answers'])
        return
    ask_question(message, current_question + 1)


def ask_regions(message):
    supported_regions = config.aws.regions
    allowed_values = '\n'.join(supported_regions)
    message.reply(QUESTION_1 % allowed_values, in_thread=True)


def ask_security_features(message):
    supported_features = [module.section for module in config.modules]
    allowed_values = '\n'.join(supported_features)
    message.reply(QUESTION_2 % allowed_values, in_thread=True)


def ask_tags(message):
    message.reply(QUESTION_3, in_thread=True)


def ask_question(message, question_number):
    QUESTIONS[question_number]['question_func'](message)


QUESTIONS = {
    0: {'parse_func': parse_regions, 'question_func': ask_regions},
    1: {'parse_func': parse_security_features, 'question_func': ask_security_features},
    2: {'parse_func': parse_tags, 'question_func': ask_tags}
}

DIALOGS = dict()
USERS = dict()


def get_current_question(thread):
    return len(DIALOGS[thread]['answers'])


@respond_to('^scan account (?P<account_num>.*)$', re.IGNORECASE)
def start_scan_conversation(message, account_num):
    try:
        thread_ts = message.body['thread_ts']
    except KeyError:
        thread_ts = None
    if not thread_ts:
        # need to start mew conversation with a user
        DIALOGS[message.body['ts']] = {'account': account_num, 'answers': []}
        user = message.user['id']
        if user in USERS:
            # remove previous conversation. you can communicate only in one thread with bot at a time
            del DIALOGS[USERS[user]]
        USERS[user] = message.body['ts']
        return ask_question(message, 0)
    if thread_ts not in DIALOGS:
        # somebody tries to start scanning in already existing slack thread that is not related to hammer scan
        # just ignore it
        return
    message.reply('Can not start new scan in this thread. Please start new thread or finish this thread first.')


@listen_to('^(?P<user_response>.*)$', re.IGNORECASE)
def handle_scan_thread_answers(message, user_response):
    try:
        thread_ts = message.body['thread_ts']
    except KeyError:
        return
    if thread_ts not in DIALOGS:
        return
    try:
        parse_answer(message, user_response, thread_ts)
    except KeyError:
        pass
    except Exception as e:
        message.reply(str(e))
