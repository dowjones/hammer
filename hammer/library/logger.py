import sys
import logging
import logging.handlers
try:
    # we do not need watchtower in lambda, so just skip it if not available
    import watchtower
except ImportError:
    pass


from boto3.session import Session


def get_formatter(level):
    """
    :param level: logging level

    :return: logging.Formatter with string based on logging level
    """
    if level == logging.DEBUG:
        return logging.Formatter("[%(levelname)s]\t%(asctime)s\t%(filename)s:%(funcName)s:%(lineno)d\t%(message)s")
    else:
        return logging.Formatter("[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(message)s")


def set_logging(ident=None, level=logging.ERROR, logfile=None):
    """
    This is a dumb method used for setting logging in cases when default logging settings should be used

    :param ident: default logging identificator. When is set it will add console stdout logging.
    :param level: default logging level
    :param logfile: name of file to log to, can be omitted

    :return: logging class instance
    """
    logger = logging.getLogger()
    logger.setLevel(level)
    logformatter = get_formatter(level)

    # running not in lambda - add stdout log
    if len(logger.handlers) == 0:
        loghandler = logging.StreamHandler()
        loghandler.setFormatter(logformatter)
        logger.addHandler(loghandler)
    # replace formatter for lambda debugging
    elif logger.handlers[0].__class__.__name__ == "LambdaLoggerHandler" and \
         level == logging.DEBUG:
        # default lambda formatter: [%(levelname)s]	%(asctime)s.%(msecs)dZ	%(aws_request_id)s	%(message)s
        logger.handlers[0].setFormatter(logformatter)

    if logfile:
        filehandler = logging.handlers.RotatingFileHandler(logfile, maxBytes=1048576, backupCount=2)
        filehandler.setFormatter(logformatter)
        logger.addHandler(filehandler)

    # suppress messages from external libraries
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    logging.getLogger('nose').setLevel(logging.CRITICAL)
    logging.getLogger('s3transfer').setLevel(logging.CRITICAL)
    logging.getLogger('requests').setLevel(logging.CRITICAL)
    logging.getLogger('oauthlib').setLevel(logging.CRITICAL)
    logging.getLogger('requests_oauthlib').setLevel(logging.CRITICAL)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.CRITICAL)
    logging.getLogger('urllib3.util.retry').setLevel(logging.CRITICAL)
    logging.getLogger('ipwhois').setLevel(logging.CRITICAL)

    return logger


def add_cw_logging(log_group, log_stream=None, level=logging.ERROR, region=None):
    """
    Adds logging to CloudWatch to current root logger

    :param log_group: name of precreated CloudWatch Log Group
    :param stream: name of CloudWatch Log Stream
    :param level: logging level for CloudWatch
    :param region: name of AWS region to use

    :return: nothing
    """
    if "watchtower" not in sys.modules:
        logging.error("CloudWatch logging was requested, but 'watchtower' is not available")
        return

    try:
        logger = logging.getLogger()
        args = {'create_log_group': False,
                'log_group': log_group,
                'stream_name': log_stream if log_stream else "default",
                'send_interval': 3,
               }
        if region:
            args['boto3_session'] = Session(region_name=region)

        cw = watchtower.CloudWatchLogHandler(**args)
        cw.setFormatter(get_formatter(level))
        logger.addHandler(cw)
    except Exception:
        logging.exception("failed to setup watchtower")
