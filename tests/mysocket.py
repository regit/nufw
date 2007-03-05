from socket import (socket,
    AF_INET, SOCK_STREAM,
    error as socket_error, timeout as socket_timeout)
from logging import info

def connectTcp(host, port, timeout=None):
    try:
        info("connectTcp(%s, %s, timeout=%s)" % (host, port, timeout))
        conn = socket(AF_INET, SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect((host,port))
        conn.close()
        info("connectTcp(%s, %s, timeout=%s): success" % (host, port, timeout))
        return True
    except socket_timeout:
        info("connectTcp(%s, %s, timeout=%s): timeout" % (host, port, timeout))
        return False
    except socket_error, err:
        info("connectTcp(%s, %s, timeout=%s): socket error: %s" % (host, port, timeout, err))
        return False

