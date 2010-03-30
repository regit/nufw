#!/bin/sh

set -e

CN=$1

cat > user.cnf << EOF
[ req ]
default_bits            = 1024
distinguished_name      = $CN
string_mask             = nombstr
req_extensions          = extensions
input_password          = secret
output_password         = secret
[ $CN ]
commonName              = Common Name
commonName_value        = $CN
commonName_max          = 64
emailAddress            = Email Address
emailAddress_value      = admin@localhost.edu
emailAddress_max        = 40
[ extensions ]
nsCertType              = client,email
basicConstraints        = critical,CA:false
keyUsage                = digitalSignature, keyEncipherment
extendedKeyUsage        = clientAuth
# This is the Microsoft NT-PRINCIPAL extension
subjectAltName          = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$CN
EOF
