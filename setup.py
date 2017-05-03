#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from setuptools import setup, find_packages
from viper.common.version import __version__

setup(
    name='viper',
    version=__version__,
    author='Claudio Guarnieri',
    author_email='nex@nex.sx',
    description="Binary Analysis & Management Framework",
    url='http://viper.li',

    scripts=['viper-cli', 'viper-api', 'viper-web', 'viper-update'],
    packages=find_packages(),
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],

    # BSD 3-Clause License:
    # - http://choosealicense.com/licenses/bsd-3-clause
    # - http://opensource.org/licenses/BSD-3-Clause
    license='BSD 3-Clause',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Topic :: Security',

        'License :: OSI Approved :: BSD License',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',

        'Operating System :: POSIX :: Linux',
    ],

    keywords='binary analysis management malware research',
)
