#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

version = '0.2'

setup(name = 'opencce',
	version = version,
	description = 'This is a free software implementation of the CCE (Citizen Card Encrypted) functionality.',
	long_description = open('README.md', 'r').read(),
	keywords = 'encryption citizencard CCE',
	classifiers = [
		'Development Status :: 4 - Beta',
		'Environment :: Console',
		'Intended Audience :: Information Technology',
		'License :: OSI Approved :: MIT License',
		'Natural Language :: English',
		'Operating System :: POSIX',
		'Programming Language :: Python :: 2.7',
		'Topic :: Utilities'
	],
	author = 'Stephan Klein',
	url = 'https://github.com/privatwolke/opencce',
	license = 'MIT',
	packages = ['opencce', 'opencce.containers'],
	install_requires = ['lxml', 'M2Crypto', 'python-magic'],
	package_dir = {
		'opencce': 'opencce'
	},
	zip_safe = True,
	entry_points = {
		'console_scripts': [
			'opencce = opencce.__main__:main'
		]
	}
)
