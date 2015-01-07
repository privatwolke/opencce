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
import getpass

import M2Crypto.BIO
import M2Crypto.SMIME
import M2Crypto.X509
import M2Crypto.EVP

from StringIO import StringIO
from collections import defaultdict

from email.parser import Parser
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.audio import MIMEAudio
from email.mime.image import MIMEImage
from email.mime.text import MIMEText

from opencce import x509
from opencce.utils import Utils


DEFAULT_CIPHER_STRING = "aes_256_cbc"


class CCEContainerFile(object):
	''' Holds a single file by reference along with some container meta data. '''

	def __init__(self, handle, name, directory):
		self.handle = handle
		self.name = name
		
		# Prevent against relative directory changes by disallowing "../"
		self.directory = directory.replace("../", "")



class CCEContainer(set):
	''' Represents a Container file compatible with the original CCE application. '''


	def __init__(self):
		''' creates an empty CCEContainer '''

		self.recipients = x509.CertificateStore()
		super(CCEContainer, self).__init__()


	def add(self, path, directory = ""):
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

		name = os.path.basename(path)
		handle = open(path, "r")

		super(CCEContainer, self).add(CCEContainerFile(handle, name, directory))


	def add_stream(self, handle, name, directory = ""):
		''' Add a new file using a stream handler. '''

		super(CCEContainer, self).add(CCEContainerFile(handle, name, directory))


	def add_recipient_certificate(self, certificate):
		''' Adds a new recipient certificate. '''

		self.recipients.add_from_file(certificate)


	def get_message(self):
		''' Returns all files in this container as MIME message instance. '''

		# Since we can add multiple files, this must be a multipart message.
		message = MIMEMultipart()

		# Add all files to the message.
		for cce_file in self:
			# Try to guess main and subtypes of the file.
			mtype, stype = Utils.get_mimetype(cce_file.name, cce_file.handle.read(1024))
			cce_file.handle.seek(0)

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
			part = mime_generator(cce_file.handle.read(),	stype)
			cce_file.handle.seek(0)

			# Assemble the file name from directory and basename.
			fname = "/".join([cce_file.directory, cce_file.name])

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


	def export(self):
		''' Generator that yields directory, filename and a handle to each file. '''

		for cce_file in self:
			# Path is delivered in components, ready for os.path.join.
			path = cce_file.directory.strip("/").split("/")
			filename = cce_file.name

			yield path, filename, cce_file.handle

		# Reset all file handles to zero.
		for cce_file in self:
			cce_file.handle.seek(0)


	def __str__(self):
		''' Returns the unencrypted MIME message as a string. '''

		return self.get_message().as_string()


	def close(self):
		''' Close the CCEContainer instance. All further behavior is unspecified. '''

		for cce_file in self:
			cce_file.handle.close()


	@staticmethod
	def load(input_stream, key, password = None):
		''' Loads a CCE container from an input stream. '''

		# If we don't get a password for the key, we prepare an interactive prompt.
		if not password:
			password_callback = lambda x: getpass.getpass("Password for " + key + ": ")
		else:
			password_callback = lambda x: password

		# Read the message and prepare the SMIME structures.
		buf = M2Crypto.BIO.MemoryBuffer(input_stream.read())
		smime = M2Crypto.SMIME.SMIME()

		# Try to load the key.
		try:
			smime.load_key(key, callback = password_callback)
		except M2Crypto.EVP.EVPError, error:
			raise IOError(error)

		# Load the PKCS#7 message and try to decrypt it.
		pkcs7, _ = M2Crypto.SMIME.smime_load_pkcs7_bio(buf)
		
		try:
			message = smime.decrypt(pkcs7)
		except M2Crypto.SMIME.PKCS7_Error, error:
			raise IOError(error)

		instance = CCEContainer()

		# Extract each message part in turn and retrieve the payload and filename.
		for part in Parser().parsestr(message).get_payload():
			struct = part.get_param("name").strip("/").split("/")
			name = struct[-1]

			stream = StringIO(part.get_payload(decode = True))

			if name == x509.CERTIFICATE_STORE_NAME:
				# We want to deal with the CertificateStore separately.
				instance.recipients = x509.CertificateStore.load(stream)
			else:
				# Add all other files to the container.
				directory = "/".join(struct[0:-1])
				instance.add_stream(stream, name, directory = directory)

		return instance
