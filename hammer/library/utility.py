import os
import json
import xml
import time
import logging
import linecache
import tracemalloc
import tempfile
import fcntl


from datetime import datetime
from decimal import Decimal


def jsonEncoder(obj):
    if isinstance(obj, datetime):
        return obj.strftime("%c")
    # moto s3 bug
    elif isinstance(obj, xml.etree.ElementTree.Element):
        return obj.text
    elif isinstance(obj, Decimal):
        # TODO: int or float?
        return int(obj)
    else:
        return None


def jsonDumps(obj, **kwargs):
    """ :return: pretty formatted dict with auto conversion for datetime, Decimal, etc """
    return json.dumps(obj, indent=4, default=jsonEncoder, **kwargs)


def list_converter(x, separator=", "): return separator.join(x) if len(x) > 0 else '-'
def empty_converter(x): return '-' if not x else x
def bool_converter(x): return 'Yes' if x else 'No'


def timeit(method):
    def timed(*args, **kw):
        start = time.perf_counter()
        result = method(*args, **kw)
        end = time.perf_counter()
        duration = (end - start)
        logging.debug(f"'{method.__name__}{pararms_to_str(*args, **kw)}' duration '{duration:.2f}'")
        return result
    return timed


def pararms_to_str(*args, **kw):
    params = ", ".join([str(arg) for arg in args])
    for k, v in kw.items():
        if params:
            params += ", "
        params += f"{k}={v}"
    return f"({params})"


# https://docs.python.org/3/library/tracemalloc.html#pretty-top
def log_top(snapshot, key_type='traceback', limit=10):
    snapshot = snapshot.filter_traces((
        tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
        tracemalloc.Filter(False, "<unknown>"),
    ))
    top_stats = snapshot.statistics(key_type)

    top = f"Top {limit} memory usage lines\n"
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        # replace "/path/to/module/file.py" with "module/file.py"
        filename = os.sep.join(frame.filename.split(os.sep)[-2:])
        top += f"#{index}. {filename}:{frame.lineno} {stat.size / 1024:.1f} KiB\n"
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            top += f"    {line}\n"

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        top += f"{len(other)} other: {size / 1024:.1f} KiB\n"
    total = sum(stat.size for stat in top_stats)
    top += f"Total allocated size: {total / 1024:.1f} KiB\n"

    logging.debug(top)


def confirm(question, default=None):
    """
    Ask confirmation question via input() and return answer.

    :param question: string that is presented to the user
    :param default: presumed answer if the user just hits <Enter>.
                    It must be True, False or None (the default, meaning
                    an answer is required of the user).

    :return: boolean with user answer.
    """
    valid = {"yes": True, "y": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default:
        prompt = " [Y/n] "
    else:
        prompt = " [y/N] "

    while True:
        print(question + prompt, end='')
        try:
            choice = input().lower()
        except EOFError:
            print()
            choice = ''

        if default is not None and choice == '':
            return default
        elif choice in valid.keys():
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no'")


class SingletonInstanceException(BaseException):
    pass


class SingletonInstance(object):
    """ Class that can be instantiated only once per instance_id to prevent
        reporting/remediation scripts from running in parallel.

        Remember that you should assign SingleInstance() to some variable available till script end
        to prevent class instance from been garbage collected thus closing file handler and releasing lock.
    """
    def __init__(self, instance_id):
        filename = f"hammer-{instance_id}.lock"
        self.lockfile = os.path.join(tempfile.gettempdir(), filename)
        self.fh = open(self.lockfile, 'w')
        try:
            fcntl.lockf(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            raise SingletonInstanceException()