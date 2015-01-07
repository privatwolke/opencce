#!/usr/bin/python

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

import argparse

from opencce.utils import Log
from opencce.containers.CCEContainer import CCEContainer


class OpenCCE(object):
	''' Provides a command line interface to the opencce module. '''

	def __init__(self):
		pass


	@staticmethod
	def run():
		''' Run the command line interface. '''

		# Parse the arguments and run the correct method based on the result.
		args = OpenCCE.parse_arguments()
		args.func(args, log = Log(args.quiet))


	@staticmethod
	def encrypt(args, log):
		''' Runs when the user uses the 'encrypt' positional argument. '''

		container = CCEContainer()

		for certificate in args.certificates:
			log.log("Adding certificate: " + certificate)
			try:
				container.add_recipient_certificate(certificate)
				log.success()
			except IOError, error:
				log.warn(error.message)

		for path in args.files:
			log.log("Adding file: " + path)
			try:
				container.add(path)
				log.success()
			except OSError, error:
				log.warn(error.message)

		with open(args.output, "wb") as handle:
			log.log("Encrypting to " + args.output)
			handle.write(container.encrypt())
			log.success()


	@staticmethod
	def decrypt(args, log):
		''' Runs when the user uses the 'dencrypt' positional argument. '''
		log.print("This is decrypt.")
		print(args)


	@staticmethod
	def parse_arguments():
		''' Parses command line arguments and returns them. '''

		# Set up the main parser.
		parser = argparse.ArgumentParser(
			description = "Perform cryptographic operations on CCE containers."
		)

		parser.add_argument(
			"-q", "--quiet",
			action = "store_true",
			help   = "suppress all log messages"
		)

		# All main functions have their own subparser.
		subparsers = parser.add_subparsers()


		# This is the 'encrypt' parser.
		encryption_parser = subparsers.add_parser("encrypt", help = "Encrypt files in a CCE container.")

		# The func parameter is later used to automatically call the correct method.
		encryption_parser.set_defaults(func = OpenCCE.encrypt)

		encryption_parser.add_argument(
			"-O", "--output",
			help    = "sets the filename of CCE container when encrypting",
			default = "Container.cce"
		)

		encryption_parser.add_argument(
			"-C", "--compress",
			action  = "store_true",
			help    = "create a compressed container (this is NOT compatible with the original CCE)"
		)

		encryption_parser.add_argument(
			"-c", "--certificates",
			nargs    = "+",
			help     = "one or more certificate keys to use for encryption or decryption",
			metavar  = "CERTIFICATE",
			required = True
		)

		encryption_parser.add_argument(
			"files",
			help = "files that should be stored and encrypted",
			nargs = "+",
			metavar = "FILE"
		)


		# This is the 'decrypt' parser.
		decryption_parser = subparsers.add_parser("decrypt", help = "Decrypt files from a CCE container.")
		decryption_parser.set_defaults(func = OpenCCE.decrypt)

		decryption_parser.add_argument(
			"-d", "--directory",
			help    = "sets the output directory for decrypted files",
		)

		decryption_parser.add_argument(
			"-k", "--key",
			nargs    = 1,
			help     = "the key to be used for decryption",
			required = True
		)

		decryption_parser.add_argument(
			"container_file",
			nargs    = 1,
			help     = "container file to be decrypted",
			metavar  = "CONTAINER"
		)

		decryption_parser.add_argument(
			"-P", "--password",
			help    = "password for the key file, if needed"
		)

		return parser.parse_args()







if __name__ == "__main__":
	OpenCCE.run()
