#!/bin/sh

# generates certificates for tests

set -e

make distclean

make CA

make cert NAME="nuauth.inl.fr" CERT_TYPE=server
make cert NAME="nufw.inl.fr" CERT_TYPE=user
make cert NAME="client.inl.fr" CERT_TYPE=user

make cert NAME="nuauth-expired.inl.fr" CERT_TYPE=server CERT_DAYS=-1
make cert NAME="nufw-expired.inl.fr" CERT_TYPE=user CERT_DAYS=-1
make cert NAME="client-expired.inl.fr" CERT_TYPE=user CERT_DAYS=-1


make cert NAME="nuauth-revoked.inl.fr" CERT_TYPE=server
make revoke NAME="nuauth-revoked.inl.fr"

make cert NAME="client-revoked.inl.fr" CERT_TYPE=user
make revoke NAME="client-revoked.inl.fr"

chmod o-rwx *.key


make gencrl
make gencrl CRL_NAME="crl-expired.pem" CRL_DAYS=-1

make clean
