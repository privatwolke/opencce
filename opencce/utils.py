#!/usr/bin/python

''' This module provides classes to encrypt and decrypt CCE container files. '''

##
## Copyright (c) 2015 Stephan Klein (@codecurry)
##
## Permission is hereby granted, free of charge, to any person obtaining
## a copy of this software and associated documentation files (the "Software"),
## to deal in the Software without restriction, including without limitation the
## rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is furnished
## to do so, subject to the following conditions:
##
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
## FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
## COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
## IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
## CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
##


from __future__ import print_function

import sys

try:
	import magic
except ImportError:
	import mimetypes


class Utils(object):
	''' Provides common utility functions. '''

	def __init__(self):
		pass


	@staticmethod
	def get_mimetype(filename):
		''' Try our best to guess the MIME type of a given file. '''

		if magic:
			mimetype = magic.from_file(filename, mime = True)
		else:
			mimetype, _ = mimetypes.guess_type(filename)
			if not mimetype:
				mimetype = "application/octet-stream"

		return tuple(mimetype.split("/", 1))



class Log(object):
	''' A simple logging class that supports partial log messages. '''

	def __init__(self, quiet):
		self.quiet = quiet


	def print(self, message):
		''' Prints a complete line to standard error. '''

		if not self.quiet:
			print(message, file = sys.stderr)


	def log(self, message):
		''' Prints an incomplete log message to standard error. '''

		if not self.quiet:
			print(message, file = sys.stderr, end = " ")


	def success(self):
		''' Completes an incomplete log message on standard error with [OK]. '''

		if not self.quiet:
			print("... [\033[0;32mOK\033[0m]", file = sys.stderr)


	def error(self, message):
		''' Completes an incomplete log message on standard error with [ERROR] (message). '''

		if not self.quiet:
			print("... [\033[0;31mERROR\033[0m] {0}".format(message), file = sys.stderr)


	def warn(self, message):
		''' Completes an incomplete log message on standard error with [WARNING] (message). '''

		if not self.quiet:
			print("... [\033[0;33mWARNING\033[0m] {0}".format(message), file = sys.stderr)
