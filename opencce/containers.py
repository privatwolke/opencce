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

import os.path

import M2Crypto.BIO
import M2Crypto.SMIME
import M2Crypto.X509

from collections import defaultdict

from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.audio import MIMEAudio
from email.mime.image import MIMEImage
from email.mime.text import MIMEText

from opencce import x509
from opencce.utils import Utils


DEFAULT_CIPHER_STRING = "aes_256_cbc"


class CCEContainer(set):
	''' Represents a Container file compatible with the original CCE application. '''


	def __init__(self):
		''' creates an empty CCEContainer '''

		self.recipients = x509.CertificateStore()
		super(CCEContainer, self).__init__()


	def add(self, filename, directory = "/"):
		'''
			Add a new file to the container using its filename. If directory is given,
			it will be used to create hierarchy in the container.


			Example
			-------

			# add a file in the root directory of the container
			container.add("file.ext")

			# add a file to the 'stuff' directory
			container.add("another_file.ext", directory = "stuff")

			# the container now contains file.ext and stuff/another_file.ext

		'''

		# Prepend '/' to the directory if necessary.
		if not directory.startswith("/"):
			directory = "/" + directory

		# Ensure that the file exists.
		try:
			path = os.path.abspath(filename)
			if os.path.isfile(path):
				super(CCEContainer, self).add((path, directory))
			else:
				raise OSError("This is not a file: " + path)
		except:
			raise OSError("This is not a file: " + str(filename))


	def add_recipient_certificate(self, certificate):
		''' Adds a new recipient certificate. '''

		self.recipients.add_from_file(certificate)


	def get_message(self):
		''' Returns all files in this container as MIME message instance. '''

		# Since we can add multiple files, this must be a multipart message.
		message = MIMEMultipart()

		# Add all files to the message.
		for path, directory in self:
			with open(path, "rb") as handle:
				# Try to guess main and subtypes of the file.
				mtype, stype = Utils.get_mimetype(path)

				# Mapping from main type to the correct Message class. Default is application/octet-stream.
				tmap = defaultdict(
					lambda: (MIMEApplication, "octet-stream"),
					{
						"application": (MIMEApplication, stype),
						"audio":       (MIMEAudio,       stype),
						"image":       (MIMEImage,       stype),
						"text":        (MIMEText,        stype)
					}
				)

				mime_generator, stype = tmap[mtype]

				# Generate the message part from the file
				part = mime_generator(handle.read(),	stype)

				# Assemble the file name from directory and basename.
				fname = "/".join([directory, os.path.basename(path)])

				# Add the file name to the headers of the MIME part.
				part.add_header("Content-Disposition", "attachment", filename = fname)
				part.set_param("name", fname)

				# Attach the message part to the main message.
				message.attach(part)

		return message


	def encrypt(self, cipher = DEFAULT_CIPHER_STRING):
		''' Performs the encryption and returns the PKCS#7 message as a string. '''

		message = self.get_message()

		# Generate and append the certificate store.
		part = MIMEApplication(self.recipients.get_archive().read(), "zip")
		part.add_header("Content-Disposition", "attachment", filename = x509.CERTIFICATE_STORE_NAME)
		part.set_param("name", x509.CERTIFICATE_STORE_NAME)
		message.attach(part)

		# Write the message to a memory buffer.
		buf = M2Crypto.BIO.MemoryBuffer(message.as_string())

		# Prepare the SMIME message and set the recipient certificates.
		smime = M2Crypto.SMIME.SMIME()
		smime.set_x509_stack(self.recipients.as_stack())

		# Set the cipher string and encrypt the memory buffer.
		smime.set_cipher(M2Crypto.SMIME.Cipher(cipher))
		pkcs7 = smime.encrypt(buf)

		# Prepare the output buffer and write the encrypted PKCS#7 message.
		out = M2Crypto.BIO.MemoryBuffer()
		smime.write(out, pkcs7)

		return out.read().strip()


	def __str__(self):
		''' Returns the unencrypted MIME message as a string. '''

		return self.get_message().as_string()


	@staticmethod
	def load(inputstream):
		''' Loads a CCE container from an input stream. '''
		pass
