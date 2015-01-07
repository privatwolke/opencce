#!/bin/bash

##
## Copyright © 2015 Stephan Klein (@codecurry)
## 
## Permission is hereby granted, free of charge, to any person obtaining
## a copy of this software and associated documentation files (the “Software”),
## to deal in the Software without restriction, including without limitation the
## rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is furnished
## to do so, subject to the following conditions:
## 
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
## 
## THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
## FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
## COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
## IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
## CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
##


echo "THIS SCRIPT IS DEPRECATED. PLEASE USE opencce-cli."


##################
## DEPENDENCIES ##
##################

MIMECONSTRUCT=/usr/bin/mime-construct
MUNPACK=/usr/bin/munpack
ZIP=/usr/bin/zip
OPENSSL=/usr/bin/openssl

if [ ! -f $MIMECONSTRUCT ]; then
  echo "Dependency missing: mime-construct was not found at $MIMECONSTRUCT"
  exit 1
fi

if [ ! -f $MUNPACK ]; then
  echo "Dependency missing: munpack was not found at $MIMECONSTRUCT"
  exit 1
fi

if [ ! -f $ZIP ]; then
  echo "Dependency missing: zip was not found at $ZIP"
  exit 1
fi

if [ ! -f $OPENSSL ]; then
  echo "Dependency missing: openssl was not found at $OPENSSL"
  exit 1
fi


# Create a temporary working directory
WORKDIR=$(mktemp -d)

# and save the current one
EXECDIR=$(pwd)


#################################
## COMMAND LINE OPTION PARSING ##
#################################


# either encrypt or decrypt
MODE=$1
shift 1

# holds the filenames of the keys or certificates
KEYS=()

# encryption: holds the file names to be encrypted
# decryption: holds the list of files to be decrypted
FILES=()

# output file
OUTFILE=Container.cce
 
while getopts ":k:o:" opt; do
  case $opt in
    k)
      if [ ! -f $OPTARG ]; then
        echo "Key not found: $OPTARG"
        exit 2
      fi
      
      KEYS+=($OPTARG)
      ;;
    o)
      OUTFILE=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# remove already processed arguments
shift $((OPTIND-1))

# capture input files
FILES=($@)

######################
# UTILITY FUNCTIONS ##
######################

function make_certstore {
  XML='<?xml version="1.0" encoding="UTF-8" standalone="no"?><certStore:XMLCertificateStore xmlns:certStore="http://www.a-sit.at/2006/12/09/XMLCertificateStore"><CertificateStoreConfiguration><FriendlyName>Memory certificate store</FriendlyName><GroupSeperator>/</GroupSeperator><Expanded>true</Expanded><GroupInformation><Group><GroupName>default</GroupName><Expanded>true</Expanded></Group></GroupInformation></CertificateStoreConfiguration>'
  
  ((n_elements=${#KEYS[@]}, max_index=n_elements - 1))
  
  for ((i = 0; i <= max_index; i++)); do
    # extract encoded certificate
    TMPKEY=$(openssl x509 -inform PEM -outform PEM -in ${KEYS[i]} | sed -e '2,$!d' -e '$d')
    
    # extract SHA-1 hash
    TMPID=$(openssl x509 -inform PEM -fingerprint -outform PEM -noout -in ${KEYS[i]} | cut -c 18- | sed -e 's/://g')
    
    # extract certificate name
    TMPNAME=$(openssl x509 -inform PEM -subject -outform PEM -noout -in ${KEYS[i]} | sed -e 's/=/\n/g' | tail -n 1)
    
    XML+="<X509Certificate><ID>$TMPID</ID><Type>0</Type><EncodedX509Certificate>$TMPKEY</EncodedX509Certificate><GroupInformation><Group><GroupName>default</GroupName><FriendlyName>$TMPNAME</FriendlyName></Group></GroupInformation></X509Certificate>"
  done
  
  XML+="</certStore:XMLCertificateStore>"
  
  echo $XML > $WORKDIR/CertificateStore
  
  cd $WORKDIR
  $ZIP -9 -r RecipientCertificates.xml.zip CertificateStore 1>/dev/null 2>/dev/null
  [ ! $? -eq 0 ] && echo "Could not create certificate store." && cd $EXECDIR && exit 3
  cd $EXECDIR
}


########################
## ENCRYPTION ROUTINE ##
########################

function encrypt {
  make_certstore
  
  MIMECMD=($MIMECONSTRUCT)
  ((n_elements=${#FILES[@]}, max_index=n_elements - 1))
  for ((i = 0; i <= max_index; i++)); do
    MIMECMD+=("--file-attach ${FILES[i]}")
  done
  
  MIMECMD+=("--file-attach $WORKDIR/RecipientCertificates.xml.zip" "--to root@localhost" "--output")
  
  ${MIMECMD[@]} > $WORKDIR/message.eml
  
  $OPENSSL smime -encrypt -aes256 -keyform X509 -in $WORKDIR/message.eml -out $OUTFILE ${KEYS[@]}
}


########################
## DECRYPTION ROUTINE ##
########################

function decrypt {
  $OPENSSL smime -decrypt -inkey $KEYS -in $FILES -keyform pkcs12 > $WORKDIR/message.eml
  mkdir "$FILES-decrypted"
  cd "$FILES-decrypted"
  $MUNPACK $WORKDIR/message.eml
  rm RecipientCertificates.xml.zip
  cd $EXECDIR
}


######################
## MAIN MODE SWITCH ##
######################

if [ $MODE == "encrypt" ]; then
  encrypt
else
  if [ $MODE == "decrypt" ]; then
    decrypt
  fi
fi


##############
## CLEAN UP ##
##############

rm -rf $WORKDIR

