#!/usr/bin/env python
# coding: utf-8

import os
import base64
import StringIO
from opencce.containers.CCEContainer import CCEContainer

CERTIFICATE = "tests/testing-certificate.pem"
KEY         = "tests/testing-key.pem"

def test_library():
	c = CCEContainer()
	c.add(CERTIFICATE)
	c.add_recipient_certificate(CERTIFICATE)
	encrypted = c.encrypt()

	assert "MIME-Version" in encrypted
	assert "filename=\"smime.p7m\"" in encrypted
	assert "application/x-pkcs7-mime" in encrypted
	assert base64.b64decode(encrypted.split("\n\n")[1])

	# test decryption
	c = CCEContainer.load(StringIO.StringIO(encrypted), KEY)
	path, filename, handle = list(c.export())[0]
	assert CERTIFICATE.split("/")[1] == filename
