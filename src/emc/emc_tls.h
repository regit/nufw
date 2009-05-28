/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#ifndef __EMC_TLS_H__
#define __EMC_TLS_H__

/**
 * Number of bits for use in an Diffie Hellman key exchange,
 * used in gnutls_dh_set_prime_bits() call.
 */
#define DH_BITS 1024

int emc_init_tls(struct emc_tls_server_context *ctx);

#endif /* __EMC_TLS_H__ */
