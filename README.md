This is `opencce`, a small application that replicates part of the functionality
provided by the [CCE (Citizen Card Encrypted)](https://joinup.ec.europa.eu/software/cce/description) software by [A-SIT](https://www.a-sit.at/).

## How `opencce`  differs…
* `opencce` is written in Python and uses only widely available libraries including `openssl`.
* `opencce` is Open Source. Please feel free to look at the code.
* `opencce` **cannot** currently use your Citizen Card (_ecard_) to perform cryptographic operations.
* `opencce` **can** be used as a library or through its command-line interface.

However, as far as I can tell, `opencce` is able to decrypt containers produced by the original software. It also produces files that are fully compatible with the original. **If you encounter a case where this is not true, please file an issue!**

### Dependencies
* [python](http://python.org) (>= 2.7)
* [python-m2crypto](https://github.com/martinpaljak/M2Crypto)
* [lxml](http://lxml.de)
* [python-magic](https://github.com/ahupp/python-magic) (optional)

### Future Plans
* Smart Card support.
* Compressed archive variant (SMIME is horrible for space efficiency).
* Install scripts, package for distributions.

### Usage
#### Encryption using `opencce-cli`
    $ ./opencce-cli encrypt -c certificate.pem another_certificate.cer -- file1.txt file.pdf
    Adding certificate: certificate.pem ... [OK]
    Adding certificate: another_certificate.cer ... [OK]
    Adding file: file1.txt ... [OK]
    Adding file: file.pdf ... [OK]
    Encrypting to Container.cce ... [OK]

#### Encryption using the Library
    >>> from opencce.containers.CCEContainer import CCEContainer
    >>> c = CCEContainer()
    >>> c.add("file1.txt")
    >>> c.add("file.pdf")
    >>> c.add_recipient_certificate("certificate.pem")
    >>> c.add_recipient_certificate("another_certificate.cer")
    >>> with open("Container.cce", "wb") as fh: fh.write(c.encrypt())

#### Decryption using `opencce-cli`
    $ ./opencce-cli decrypt -k key.pem -d Container Container.cce
    Decrypting container: Container.cce ... [OK]
    Making sure that the extraction directory is clean: . ... [OK]
    Extracting file: Container/file1.txt ... [OK]
    Extracting file: Container/file.pdf ... [OK]

#### Decryption using the Library
    >>> from opencce.containers.CCEContainer import CCEContainer
    >>> with open("Container.cce", "rb") as fh: c = CCEContainer.load(fh, "key.pem")
    >>> for path, filename, handle in c.export(): # do something with those files
