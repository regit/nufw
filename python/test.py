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
    NuclientError, Nuclient)

def main():
    from sys import exit, stderr

    version = nu_get_version()
    print "Version: %r" % version
    print "Check version: %r" % bool(nu_check_version(version))
    print "Home: %r" % nu_get_home_dir()

    try:
        nuclient = Nuclient(u'user', u'password')
        nuclient.connect('192.168.0.2')
    except NuclientError, error:
        print >>stderr, str(error)
        exit(1)
    except KeyboardInterrupt:
        print >>stderr, "Interrupted!"
        exit(1)

if __name__ == "__main__":
    main()

