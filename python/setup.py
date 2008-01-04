#!/usr/bin/python
from imp import load_source
from os import path
import sys

if "--setuptools" in sys.argv:
    sys.argv.remove("--setuptools")
    from setuptools import setup
else:
    from distutils.core import setup

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Development Status :: 5 - Production/Stable',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python',
]

def main():
    nuclient = load_source("version", path.join("nuclient", "version.py"))
    install_options = {
        "name": "nuclient",
        "version": nuclient.VERSION,
        "url": nuclient.WEBSITE,
        "download_url": nuclient.WEBSITE,
        "author": "Victor Stinner",
        "description": "Python binding of libnuclient library, object oriented",
        "long_description": open('README').read(),
        "classifiers": CLASSIFIERS,
        "license": nuclient.LICENCE,
        "packages": ["nuclient"],
        "package_dir": {"nuclient": "nuclient"},
    }
    setup(**install_options)

if __name__ == "__main__":
    main()

