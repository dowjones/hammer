import logging


from botocore.exceptions import ClientError
from library.utility import jsonDumps


class CloudTrail(object):
    """
    Basic class for CloudTrail.
    Encapsulates `TrailARN`/`IsLogging`/`IsMultiRegionTrail`/`HomeRegion` and list of endpoints and custom event selectors
    """
    def __init__(self, account, source, status):
        self.account = account
        self.source = source
        self.status = status
        self.name = self.source["Name"]
        self.id = self.source["TrailARN"]
        # Whether the CloudTrail is currently logging AWS API calls
        self.enabled = self.status["IsLogging"]
        # Specifies whether the trail belongs only to one region or exists in all regions
        self.multi_region = self.source["IsMultiRegionTrail"]
        # The region in which the trail was created.
        self.home_region = self.source["HomeRegion"]
        self.custom_event_selectors = []
        self.endpoints = {
            's3': {
                # Name of the Amazon S3 bucket into which CloudTrail delivers your trail files.
                'resource': self.source["S3BucketName"],
                # Displays any Amazon S3 error that CloudTrail encountered when attempting
                # to deliver log files to the designated bucket
                'error': self.status.get("LatestDeliveryError", None)
            },
            # 'sns': {
            #     # Specifies the ARN of the Amazon SNS topic that CloudTrail uses to send notifications when log files are delivered.
            #     'resource': self.source.get("SnsTopicARN"),
            #     # Displays any Amazon SNS error that CloudTrail encountered when attempting to send a notification.
            #     'error': self.status.get("LatestNotificationError", None),
            # },
            'cloudwatch': {
                # Specifies an Amazon Resource Name (ARN), a unique identifier that represents
                # the log group to which CloudTrail logs will be delivered.
                'resource': self.source.get("CloudWatchLogsLogGroupArn", None),
                # Displays any CloudWatch Logs error that CloudTrail encountered when attempting to deliver logs to CloudWatch Logs.
                'error': self.status.get("LatestCloudWatchLogsDeliveryError", None),
            }
        }

    def __str__(self):
        return (f"{self.__class__.__name__}("
                f"Name={self.name}, "
                f"Id={self.id}, "
                f"Enabled={self.enabled}, "
                f"Selectors={self.selectors}, "
                f"MultiRegion={self.multi_region}, "
                f"HomeRegion={self.home_region}, "
                f"Bucket={self.endpoints['s3']['resource']}"
               )

    @property
    def errors(self):
        """ :return: dict with all endpoints with delivery error """
        return {endpoint: props for endpoint, props in self.endpoints.items() if props['error']}

    @property
    def selectors(self):
        """ :return: string with comma-separated list of event selectors configured for trail or `All` (default value) """
        return ','.join(self.custom_event_selectors) if self.custom_event_selectors else 'All'

    @selectors.setter
    def selectors(self, selectors):
        """
        Collect custom event selectors configured for trail to simple list

        :param selectors: `EventSelectors` as AWS returns for `get_event_selectors` API call
        :return: nothing
        """
        for selector in selectors:
            self.custom_event_selectors.append(selector['ReadWriteType'])


class CloudTrailChecker(object):
    """
    Basic class for checking CloudTrail status in account.
    Encapsulates discovered CloudTrails.
    """
    def __init__(self, account):
        """
        :param account: `Account` instance with RDS snapshots to check
        """
        self.account = account
        self.trails = []

    def get_trail(self, id):
        """
        :return: `CloudTrail` by id (ARN)
        """
        for trail in self.trails:
            if trail.id == id:
                return trail
        return None

    @property
    def disabled(self):
        """
        :return: True - if no trails exist for account region or all available trails are disabled,
                 False - otherwise
        """
        return all([not trail.enabled for trail in self.trails])

    @property
    def delivery_errors(self):
        """
        :return: True - if any enabled trail has errors,
                 False - otherwise
        """
        return any([trail.enabled and trail.errors for trail in self.trails])

    def check(self):
        """
        Walk through CloudTrails in the account/region.
        Put all gathered CloudTrails to `self.trails`.

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            # get all trails
            trails = self.account.client("cloudtrail").describe_trails(
                includeShadowTrails=True
            )["trailList"]
        except ClientError as err:
            if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                logging.error(f"Access denied in {self.account} "
                              f"(cloudtrail:{err.operation_name})")
            else:
                logging.exception(f"Failed to describe CloudTrails in {self.account}")
            return False

        logging.debug(f"Discovered trails\n{jsonDumps(trails)}")
        for trail in trails:
            arn = trail["TrailARN"]
            try:
                # get each trail status (is logging and delivery errors)
                status = self.account.client("cloudtrail").get_trail_status(
                    Name=arn
                )
            except ClientError as err:
                if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                    logging.error(f"Access denied in {self.account} "
                                  f"(cloudtrail:{err.operation_name})")
                else:
                    logging.exception(f"Failed to get '{arn}' status in {self.account}")
                continue
            logging.debug(f"{arn} status\n{jsonDumps(status)}")

            tr = CloudTrail(self.account, trail, status)
            self.trails.append(tr)

            if trail['HasCustomEventSelectors']:
                try:
                    # get trail custom selectors (if not `All`)
                    selectors = self.account.client("cloudtrail").get_event_selectors(
                        TrailName=arn
                    )['EventSelectors']
                except ClientError as err:
                    if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
                        logging.error(f"Access denied in {self.account} "
                                      f"(cloudtrail:{err.operation_name})")
                    else:
                        logging.exception(f"Failed to get '{arn}' status in {self.account}")
                    continue
                logging.debug(f"{arn} custom selectors\n{jsonDumps(selectors)}")
                tr.selectors = selectors
        return True
