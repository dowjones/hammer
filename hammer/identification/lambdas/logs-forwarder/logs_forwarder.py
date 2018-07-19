import base64
import gzip
import json
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import AWSMetric, AWSMetricUnits, CloudWatch
from library.slack_utility import SlackNotification


class LogsParser(object):
    def __init__(self):
        self.config = Config()
        self.slack = SlackNotification(self.config)

    def logs_event(self, event):
        data = event.get('awslogs', {}).get('data', "")
        if not data:
            return

        compressed = base64.b64decode(data)
        decompressed = gzip.decompress(compressed)
        # https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html#LambdaFunctionExample
        payload = json.loads(decompressed)
        logGroup = payload["logGroup"]
        func_name = logGroup.split("/")[-1]
        #logStream = payload["logStream"]
        #logging.debug(f"Events from {logGroup}:{logStream}")
        for event in payload["logEvents"]:
            msg = event["message"].strip()

            # lambda report
            if msg.startswith("REPORT"):
                # ['REPORT RequestId: 250b44f1-34c4-11e8-a445-19ebd54324bc', 'Duration: 3106.46 ms', 'Billed Duration: 3200 ms ', 'Memory Size: 256 MB', 'Max Memory Used: 41 MB']
                msg = msg.split("\t")
                memory_configured = msg[3].split(":")[1].split()[0]
                memory_used = msg[4].split(":")[1].split()[0]
                func_name = logGroup.split("/")[-1]
                CloudWatch.put_lambda_metrics(
                    func_name,
                    AWSMetric(
                        name="MaxMemoryUsed",
                        value=int(memory_used),
                        unit=AWSMetricUnits.mb
                    )
                )
                if int(memory_used) >= int(memory_configured):
                    self.slack.post_message(f"Function '{func_name}' tried to use more memory ({memory_used}) than configured ({memory_configured})")
            else:
                if 'Task timed out after' in msg:
                    msg += f" ({func_name})"
                self.slack.post_message(msg)

    def sns_event(self, event):
        for record in event.get('Records', []):
            msg = record.get('Sns', {}).get('Message', {})
            if not msg or 'AlarmName' not in msg:
                self.slack.post_message(f"Unknown SNS message: '{msg}'")
                return
            if isinstance(msg, str):
                msg = json.loads(msg)
            alarm_name = msg['AlarmName']
            old_state = msg['OldStateValue']
            new_state = msg['NewStateValue']
            reason = msg['NewStateReason']
            text = f"[ALARM] {alarm_name} has changed {old_state} -> {new_state} ({reason})"
            self.slack.post_message(text)


def lambda_handler(event, context):
    set_logging(level=logging.INFO)
    parser = LogsParser()

    #logging.debug(f"get event\n{event}")
    if 'awslogs' in event:
        parser.logs_event(event)
    elif 'Records' in event:
        parser.sns_event(event)