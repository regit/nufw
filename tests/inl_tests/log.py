import atexit
from sys import stdout
from logging import FileHandler, Formatter, StreamHandler, \
    DEBUG, ERROR, getLogger

_setup_log = False

class CustomLogHandler(StreamHandler):
    def __init__(self):
        StreamHandler.__init__(self)

    def emit(self, record):
        if record.levelno < ERROR:
            return
        print "%s: %s" % (record.levelname, record.msg)

def setupLog(filename="tests.log", format='%(created).3f| %(message)s'):
    """
    Setup log system
    """
    global _setup_log
    if _setup_log:
        return
    _setup_log = True

    # Set debug level to 'DEBUG'
    logger = getLogger()
    logger.setLevel(DEBUG)

    # Write all logs in a file (LOG_FILENAME)
    if filename:
        handler = FileHandler(filename, 'w')
        handler.setFormatter(Formatter(format, None))
        logger.addHandler(handler)

        # Display error to stdout with specific handler
        handler = CustomLogHandler()
        logger.addHandler(handler)
        atexit.register(lambda: stdout.write("Log written to %s\n" % filename))

