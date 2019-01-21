import logging


from library.logger import set_logging
from moto import mock_sts


def pytest_sessionstart(session):
    if session.config.option.verbose > 2:
        set_logging(level=logging.DEBUG) #, logfile="tests.log")

    mock_sts().start()
