#!/usr/bin/python

# Copyright(C) 2007 INL
# Written by Victor Stinner <victor.stinner@inl.fr>
#
# $Id$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

"""
Example of libnuclient use
"""

from nuclient import (
    nu_get_version, nu_check_version, nu_get_home_dir,
    NuclientError, Nuclient, DEFAULT_PORT)
from optparse import OptionParser
from sys import exit, stderr
from time import sleep

def parseOptions():
    parser = OptionParser(usage="%prog -u USERNAME -p PASSWORD HOSTNAME [options]]")
    parser.add_option("--username", "-u", help="NuFW username",
        action="store", type="str", default=None)
    parser.add_option("--password", "-p", help="NuFW password",
        action="store", type="str", default=None)
    parser.add_option("--port", help="NuFW port number (default: %s)" % DEFAULT_PORT,
        type="int", default=None)
    options, arguments = parser.parse_args()
    if len(arguments) != 1 \
    or not options.username \
    or not options.password:
        parser.print_help()
        exit(1)
    return options, arguments[0]

def makeUnicode(text):
    # FIXME: Detect command line charset
    return unicode(text, 'utf8')

def main():
    options, hostname = parseOptions()

#    version = nu_get_version()
#    print "Version: %r" % version
#    print "Check version: %r" % bool(nu_check_version(version))
#    print "Home: %r" % nu_get_home_dir()
#    print

    try:
        username = makeUnicode(options.username)
        password = makeUnicode(options.password)

        try:
            nuclient = Nuclient(username, password)
            nuclient.verbose(False)
            if options.port:
                port = str(options.port)
            else:
                port = None
            nuclient.connect(hostname, port)
        except KeyboardInterrupt:
            print >>stderr, "Interrupted!"
            exit(1)

        try:
            print "Connected to %s" % hostname
            while nuclient.check():
                sleep(1)
            print "Lost connection!"
        except KeyboardInterrupt:
            print >>stderr, "Quit."
    except NuclientError, error:
        print >>stderr, str(error)
        exit(1)

if __name__ == "__main__":
    main()

