/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#ifndef __EMC_DATA_PARSER_H__
#define __EMC_DATA_PARSER_H__

/** \brief Parse EMC data file
 */
int emc_parse_datafile(struct emc_server_context *ctx, const char *file);

#endif /* __EMC_DATA_PARSER_H__ */
