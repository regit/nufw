from socket import (socket,
    AF_INET, SOCK_STREAM,
    error as socket_error, timeout as socket_timeout)

def connectTcp(host, port, timeout=None):
    try:
        conn = socket(AF_INET, SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect((host,port))
        conn.close()
        return True
    except socket_timeout:
        return False
    except socket_error, err:
        return False

