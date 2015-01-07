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
import argparse
import tempfile

import M2Crypto.BIO
import M2Crypto.SMIME
import M2Crypto.X509

import lxml.etree
import lxml.builder

from collections import defaultdict

from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.audio import MIMEAudio
from email.mime.image import MIMEImage
from email.mime.text import MIMEText

from zipfile import ZipFile, ZIP_DEFLATED


try:
	import magic
except ImportError:
	import mimetypes


# Constant values, used all over this module.

ASIT_NAMESPACE               = "http://www.a-sit.at/2006/12/09/XMLCertificateStore"
CERTIFICATE_STORE_NAME_INNER = "CertificateStore"
CERTIFICATE_STORE_NAME       = "RecipientCertificates.xml.zip"
CERTIFICATE_GROUP_NAME       = "opencce certificates"
DEFAULT_CIPHER_STRING        = "aes_256_cbc"


# ElementMaker instances the the root (EE) and all other elements (E).

EE = lxml.builder.ElementMaker(namespace = ASIT_NAMESPACE, nsmap = {"certStore": ASIT_NAMESPACE})
E  = lxml.builder.ElementMaker()



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



class CertificateStore(set):
	''' A simple data structure that stores X509 certificates. '''

	def add(self, certificate):
		''' Adds a new certificate from a string buffer in either CER/DER or PEM format. '''

		try:
			cer = M2Crypto.X509.load_cert_string(certificate, M2Crypto.X509.FORMAT_DER)
		except M2Crypto.X509.X509Error:
			try:
				cer = M2Crypto.X509.load_cert_string(certificate, M2Crypto.X509.FORMAT_PEM)
			except:
				raise IOError("Could not load certificate (unknown format).")

		super(CertificateStore, self).add(cer)


	def add_from_file(self, filename):
		''' Adds a new certificate from a filename in either CER/DER or PEM format. '''

		return self.add(open(filename, "r").read())


	def get_archive(self):
		''' Creates a CCE compliant RecipientStore.xml.zip file and returns a handle to it. '''

		# Build the CertificateStoreConfiguration element.
		# Everything here is required or the Container won't open in the original CCE program.
		xml = EE.XMLCertificateStore(
			E.CertificateStoreConfiguration(
				E.FriendlyName("opencce store"),
				E.GroupSeperator("/"), # note the mispelled element name
				E.Expanded("true"),
				E.GroupInformation(
					E.Group(
						E.GroupName(CERTIFICATE_GROUP_NAME),
						E.Expanded("true")
					)
				)
			)
		)

		# Add all certificates in the store.
		for cer in self:

			# The ID is the SHA-1 fingerprint value.
			param_id = cer.get_fingerprint(md = "sha1")

			# The EncodedX509Certificate element expects PEM format without the first and last lines.
			param_body = "\n".join(cer.as_pem().strip().split("\n")[1:-1])

			# This value is displayed as the key name in CCE.
			param_name = "{subject} ({issuer})".format(
				subject = cer.get_subject().commonName,
				issuer  = cer.get_issuer().commonName
			)

			# Build the actual X509Certificate element.
			xml.append(
				E.X509Certificate(
					E.ID(param_id),
					E.Type("0"),
					E.EncodedX509Certificate(param_body),
					E.GroupInformation(
						E.Group(
							E.GroupName(CERTIFICATE_GROUP_NAME),
							E.FriendlyName(param_name)
						)
					)
				)
			)

		xml_text = lxml.etree.tostring(xml, xml_declaration = True, encoding = "utf-8")

		# We create the ZIP archive as a temporary file.
		archive = tempfile.TemporaryFile()

		try:
			# Try to use ZIP_DEFLATED.
			zipfile = ZipFile(archive, "w", ZIP_DEFLATED)
		except RuntimeError:
			# If zlib is not available, we default to ZIP_STORED
			zipfile = ZipFile(archive, "w")

		zipfile.writestr(CERTIFICATE_STORE_NAME_INNER, xml_text)
		zipfile.close()

		# Rewind the file handle so we can read it again later.
		archive.seek(0)

		return archive


	def as_stack(self):
		''' Returns the certificates as a M2Crypto X509_Stack instance. '''

		stack = M2Crypto.X509.X509_Stack()

		for certificate in set(self):
			stack.push(certificate)

		return stack


	@staticmethod
	def load(input_stream):
		''' Create a new instance from a file handle pointing to data created by get_archive(). '''

		with ZipFile(input_stream, "r") as zipfile:
			with zipfile.open(CERTIFICATE_STORE_NAME_INNER) as xmlfile:
				xml = lxml.etree.parse(xmlfile)

		instance = CertificateStore()

		for certificate in xml.findall("X509Certificate"):
			encoded_certificate = certificate.find("EncodedX509Certificate").text
			instance.add("\n".join([
				"-----BEGIN CERTIFICATE-----", encoded_certificate, "-----END CERTIFICATE-----"
			]))

		return instance



class CCEContainer(set):
	''' Represents a Container file compatible with the original CCE application. '''


	def __init__(self):
		''' creates an empty CCEContainer '''

		self.recipients = CertificateStore()
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
		part.add_header("Content-Disposition", "attachment", filename = CERTIFICATE_STORE_NAME)
		part.set_param("name", CERTIFICATE_STORE_NAME)
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



class OpenCCE(object):
	''' Provides a command line interface to the opencce module. '''

	def __init__(self):
		pass


	@staticmethod
	def run():
		''' Run the command line interface. '''

		args = OpenCCE.parse_arguments()
		print args


	@staticmethod
	def parse_arguments():
		''' Parses command line arguments and returns them. '''

		parser = argparse.ArgumentParser(
			description = "Perform cryptographic operations on CCE containers."
		)

		group = parser.add_mutually_exclusive_group(required = True)

		group.add_argument(
			"-e", "--encrypt",
			nargs   = "*",
			help    = "encrypt supplied files",
			metavar = "file.ext"
		)

		group.add_argument(
			"-d", "--decrypt",
			help    = "decrypt from supplied container",
			metavar = "Container.cce"
		)

		parser.add_argument(
			"-o", "--output",
			help    = "sets the filename of CCE container when encrypting",
			default = "Container.cce",
			metavar = "Container.cce"
		)

		parser.add_argument(
			"-c", "--certificates",
			nargs   = "*",
			help    = "one or more certificates to use for encryption or decryption",
			metavar = "certificate"
		)

		return parser.parse_args()



if __name__ == "__main__":
	OpenCCE.run()
