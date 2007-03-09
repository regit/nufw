import atexit
from sys import stdout
from logging import basicConfig, DEBUG, ERROR, StreamHandler, getLogger

LOG_FILENAME = 'tests.log'
LOG_FORMAT = '%(created).3f| %(message)s'

_setup_log = False

class CustomLogHandler(StreamHandler):
    def __init__(self):
        StreamHandler.__init__(self)

    def emit(self, record):
        if record.levelno < ERROR:
            return
        print "%s: %s" % (record.levelname, record.msg)

def setupLog():
    """
    Setup log system
    """
    global _setup_log
    if _setup_log:
        return
    _setup_log = True
    basicConfig(
        level=DEBUG,
        format=LOG_FORMAT,
        filename=LOG_FILENAME,
        filemode='w')
    logger = getLogger()
    handler = CustomLogHandler()
    logger.addHandler(handler)
    atexit.register(lambda: stdout.write("Log written to %s\n" % LOG_FILENAME))

