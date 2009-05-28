/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#ifndef __EMC_PROTO_H__
#define __EMC_PROTO_H__

enum emc_proto_version_t {
	PROTO_VERSION_EMC_V1 = 1,
};

enum emc_command_t {
	EMC_NOP = 0,
	EMC_HELLO,
	EMC_CLIENT_CONNECTION_REQUEST,
};

#endif /* __EMC_PROTO_H__ */
