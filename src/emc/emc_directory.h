/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#ifndef __EMC_DIRECTORY_H__
#define __EMC_DIRECTORY_H__

/** \brief Structure for netmask
 */
struct emc_netmask_t {
	u_int16_t af_family;

	union {
		u_int32_t u4;
		u_int32_t u16[4];
	} ip;

	union {
		u_int32_t u4;
		u_int32_t u16[4];
	} mask;

	u_int16_t length;

	char *nuauth_server;
};

int emc_netmask_order_func (gconstpointer a, gconstpointer b);

int emc_netmask_is_included(struct emc_netmask_t*netmask, const char *ip);

#endif /* __EMC_DIRECTORY_H__ */
