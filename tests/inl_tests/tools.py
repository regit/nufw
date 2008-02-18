from errno import EEXIST
from os import rename, makedirs, access, F_OK
from logging import info
from errno import ENOENT, EACCES
from os.path import dirname

def tryRename(before, after):
    """
    Try to rename file 'before' to 'after'.
    Return True on sucess, False if original file doesn't exist.
    Raise RuntimeError() on permission error.
    """
    try:
        if access(after, F_OK):
            raise RuntimeError('New filename already exists: %s' % after)
        rename(before, after)
        return True
    except OSError, err:
        code = err[0]
        if code == ENOENT:
            info("Unable to rename %r to %r: original file doesn't exist" % (before, after))
            return False
        if code == EACCES:
            raise RuntimeError('Permission denied (retry program with root access)')
        raise

def createPath(filename):
    """
    Create directory for specified filename.
    Safe version of makedirs(dirname(filename)): ignore EEXIST error.

    Return True if one or more directory has been created, False otherwise.
    """
    path = dirname(filename)
    if not path:
        return False
    try:
        makedirs(path)
        return True
    except OSError, err:
        if err.errno == EEXIST:
            return False
        else:
            raise

