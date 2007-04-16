#!/usr/bin/env python
# $Id: setup.py 671 2004-08-22 21:02:29Z md $

import sys
if "--setuptools" in sys.argv:
    sys.argv.remove("--setuptools")
    from setuptools import setup
else:
    from distutils.core import setup

# Open IPy.py to read version
from imp import load_source
IPy = load_source("IPy", "IPy.py")

LONG_DESCRIPTION = "Command line program to control nuauth daemon throw UNIX socket"
CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: System Administrators',
    'Environment :: Console',
    'Topic :: System :: Networking',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python']
URL = "http://software.inl.fr/trac/trac.cgi/wiki/EdenWall/NuFW"

setup(name="nuauth_command",
      version=IPy.__version__,
      description="Command line program to control NuFW firewall (nuauth)",
      long_description=LONG_DESCRIPTION,
      author="Victor Stinner",
      maintainer="Victor Stinner",
      maintainer_email="victor.stinner AT inl.fr",
      license='GNU GPL v2',
      url=URL,
      download_url=URL,
      classifiers= CLASSIFIERS,
      py_modules=["IPy"])

