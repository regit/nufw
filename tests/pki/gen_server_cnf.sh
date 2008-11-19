#!/bin/sh

set -e

CN=$1

cat > server.cnf << EOF
[ req ]
default_bits                    = 1024
distinguished_name              = $CN
string_mask                     = nombstr
req_extensions                  = extensions
input_password                  = secret
output_password                 = secret
[ $CN ]
countryName                     = Country Code
countryName_value               = FR
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State Name
stateOrProvinceName_value       = France
localityName                    = Locality Name
localityName_value              = Paris
organizationName                = Organization Name
organizationName_value          = INL
organizationalUnitName          = Organizational Unit Name
organizationalUnitName_value    = INL tests
commonName                      = Common Name
commonName_value                = $CN
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_value              = admin@localhost.edu
emailAddress_max                = 40
[ extensions ]
nsCertType                      = server
basicConstraints                = critical,CA:false
# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
# do *not* include email address in subject name (CN field)
subjectAltName                  = email:move
EOF
