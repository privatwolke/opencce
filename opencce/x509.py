#!/usr/bin/env python
# coding: utf-8

''' This module provides functionality related to X509 certificates. '''

##
## Copyright (c) 2015 Stephan Klein (@privatwolke)
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

import tempfile
import lxml.etree
import lxml.builder
import M2Crypto.X509

from zipfile import ZipFile, ZIP_DEFLATED


ASIT_NAMESPACE               = "http://www.a-sit.at/2006/12/09/XMLCertificateStore"
CERTIFICATE_STORE_NAME_INNER = "CertificateStore"
CERTIFICATE_STORE_NAME       = "RecipientCertificates.xml.zip"
CERTIFICATE_GROUP_NAME       = "opencce certificates"


E  = lxml.builder.ElementMaker()
EE = lxml.builder.ElementMaker(
	namespace = ASIT_NAMESPACE,
	nsmap = {"certStore": ASIT_NAMESPACE}
)


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

		zipfile = ZipFile(input_stream, "r")
		xmlfile = zipfile.open(CERTIFICATE_STORE_NAME_INNER)
		xml = lxml.etree.parse(xmlfile)

		xmlfile.close()
		zipfile.close()

		instance = CertificateStore()

		for certificate in xml.findall("X509Certificate"):
			encoded_certificate = certificate.find("EncodedX509Certificate").text
			instance.add("\n".join([
				"-----BEGIN CERTIFICATE-----", encoded_certificate, "-----END CERTIFICATE-----"
			]))

		return instance
