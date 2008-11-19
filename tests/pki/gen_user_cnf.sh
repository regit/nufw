#!/bin/sh

set -e

CN=$1

cat > user.cnf << EOF
[ req ]
default_bits            = 1024
distinguished_name      = admin
string_mask             = nombstr
req_extensions          = extensions
input_password          = secret
output_password         = secret
[ admin ]
commonName              = $CN
commonName_value        = user
commonName_max          = 64
emailAddress            = Email Address
emailAddress_value      = admin@localhost.edu
emailAddress_max        = 40
[ extensions ]
nsCertType              = client,email
basicConstraints        = critical,CA:false
EOF
