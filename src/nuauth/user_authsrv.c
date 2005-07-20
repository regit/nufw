/*
 * Copyright(C) 2004-2005 INL http://www.inl.fr/
 ** written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <vincent@inl.fr>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 2 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define _GNU_SOURCE
#include <auth_srv.h>
#include <crypt.h>
#include <sys/time.h>
#include <sasl/saslutil.h>


static connection * userpckt_decode(struct buffer_read * datas);

/**
 * get user datas (containing datagram) and goes till inclusion (or decision) on packet.
 *
 * - Argument 1 : datagram
 * - Argument 2 : unused
 * - Return : None
 */

void user_check_and_decide (gpointer userdata, gpointer data)
{
	connection * conn_elt=NULL;
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
		g_message("entering user_check\n");
#endif
	conn_elt = userpckt_decode(userdata);
	/* if OK search and fill */
	if ( conn_elt != NULL ) {
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)){
			g_message("User : %s",conn_elt->username);
			print_connection(conn_elt,NULL);
		}
#endif
		g_async_queue_push (connexions_queue,conn_elt);
		/* free userdata, packet is parsed now */
		g_free(((struct buffer_read *)userdata)->buf);
		g_free(userdata);
	}
	else {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER)){
			g_message("User packet decoding failed\n");
		}
	}
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
		g_message("leaving user_check\n");
#endif
}

/**
 *decode user dgram packet and fill a connection with datas.
 *
 * - Argument 1 : datagram
 * - Argument 2 : size of datagram
 * - Return : pointer to newly allocated connection
 */

static connection * userpckt_decode(struct buffer_read * datas)
{
	char * dgram = datas->buf;
	connection* connexion=NULL;
	struct nuv2_header* header=(struct nuv2_header*)dgram;
	gboolean multiclient_ok=FALSE;


	/* decode dgram */
	switch (header->proto) {
		case 0x2:
			{
				switch (header->msg_type){
					case USER_REQUEST :
						{ char* start=dgram+4;
							connexion = g_new0( connection,1);
							connexion->acl_groups=NULL;
							connexion->user_groups=NULL;
							connexion->appname=NULL;
							connexion->appmd5=NULL;
							connexion->username=NULL;
							connexion->cacheduserdatas=NULL;

							while (start<dgram+header->length){
								struct nuv2_authreq* authreq=(struct nuv2_authreq* )start;
								char *req_start=start;
								req_start+=4;
								while(req_start-start<authreq->packet_length){
									struct nuv2_authfield* field=(struct nuv2_authfield* )req_start;
									switch (field->type) {
										case IPV4_FIELD:
											{
												struct nuv2_authfield_ipv4 * ipfield=(struct nuv2_authfield_ipv4 * )req_start; 

												connexion->tracking_hdrs.saddr=ipfield->src;
												connexion->tracking_hdrs.daddr=ipfield->dst;
												connexion->tracking_hdrs.protocol=ipfield->proto;

#ifdef DEBUG_ENABLE
												if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
													g_message("got IPV4 field");
#endif
												switch (connexion->tracking_hdrs.protocol) {
													case IPPROTO_TCP:
														connexion->tracking_hdrs.source=ipfield->sport;
														connexion->tracking_hdrs.dest=ipfield->dport;
														connexion->tracking_hdrs.type=0;
														connexion->tracking_hdrs.code=0;
														break;
													case IPPROTO_UDP:
														connexion->tracking_hdrs.source=ipfield->sport;
														connexion->tracking_hdrs.dest=ipfield->dport;
														connexion->tracking_hdrs.type=0;
														connexion->tracking_hdrs.code=0;
														break;
													case IPPROTO_ICMP:
														connexion->tracking_hdrs.source=0;
														connexion->tracking_hdrs.dest=0;
														connexion->tracking_hdrs.type=ipfield->sport;
														connexion->tracking_hdrs.code=ipfield->dport;
														break;
												}
											}
											break;
										case APP_FIELD:
											{
												struct nuv2_authfield_app * appfield=(struct nuv2_authfield_app* )req_start; 
#ifdef DEBUG_ENABLE
												if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
													g_message("got APP field");
#endif
												switch (appfield->option) {
													default:
														{
															unsigned int len=appfield->length-4;
															unsigned int reallen=0;
															gchar* dec_appname=NULL;

															if (8*len > 2048){
																/* it is reaaally long, we ignore packet (too lasy to kill client) */
																if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
																	g_warning("user packet announced a too long app name\n");
																free_connection(connexion);
																free_buffer_read(datas);
																return NULL;
															}
															dec_appname =	g_new0(gchar,8*len);
															if (sasl_decode64((char*)appfield+4,len, dec_appname,8*len,&reallen) 
																	==
																	SASL_BUFOVER) {
																dec_appname=g_try_realloc(dec_appname,reallen+1);
																if (dec_appname)
																	sasl_decode64((char*)appfield+4,len, dec_appname,reallen,&reallen) ;
															} else {
																dec_appname=g_try_realloc(dec_appname,reallen+1);
															}
															dec_appname[reallen]=0;

															if (dec_appname != NULL)
															{
																connexion->appname= string_escape(dec_appname);
																if (connexion->appname == NULL)
																	if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
																		g_warning("user packet received an invalid app name\n");
															}else{
																connexion->appname=NULL;
															}
															g_free(dec_appname);
															connexion->appmd5=NULL;

														}

												}
											}
											break;
										case USERNAME_FIELD:
											{
												struct nuv2_authfield_username * usernamefield=(struct nuv2_authfield_username* )req_start; 
#ifdef DEBUG_ENABLE
												if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
													g_message("got Username field");
#endif
												if (header->option == 0x1) {
													switch (usernamefield->option) {
														default:
															{
																unsigned int len=usernamefield->length-4;
																unsigned int reallen=0;
																gchar* dec_fieldname=NULL;

																if (8*len > 2048){
																	/* it is reaaally long, we ignore packet (too lasy to kill client) */
																	if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
																		g_warning("user packet announced a too long user name\n");
																	free_connection(connexion);
																	free_buffer_read(datas);
																	return NULL;
																}
																dec_fieldname =	g_new0(gchar,8*len);
																if (sasl_decode64((char*)usernamefield+4,len, dec_fieldname,8*len,&reallen) 
																		==
																		SASL_BUFOVER) {
																	dec_fieldname=g_try_realloc(dec_fieldname,reallen+1);
																	if (dec_fieldname)
																		sasl_decode64((char*)usernamefield+4,len, dec_fieldname,reallen,&reallen) ;
																} else {
																	dec_fieldname=g_try_realloc(dec_fieldname,reallen+1);
																}
																dec_fieldname[reallen]=0;

																if (dec_fieldname != NULL)
																{
																	connexion->username= string_escape(dec_fieldname);
																	if (connexion->username == NULL)
																		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
																			g_warning("user packet received an invalid username\n");
																}else {
																	g_free(dec_fieldname);
																	free_connection(connexion);
																	if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER)){
																		g_message("rejected packet, invalid username field");
																	}
																	free_buffer_read(datas);
																	return NULL;
																}
																g_free(dec_fieldname);
															}
													}
													multiclient_ok=TRUE;
												} else {
													/* should not be here */
													free_connection(connexion);
													if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER)){
														g_message("not multiuser client but sent username field");
													}
													free_buffer_read(datas);
													return NULL;
												}

											}
											break;
										default:
											if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
												g_message("unknown field type : %d",field->type);
											free_connection(connexion);
											free_buffer_read(datas);
											return NULL;
									}
									req_start+=field->length;
								}
								start+=authreq->packet_length;
							}
							/* here all packet related information are filled-in */
							if (connexion->username == NULL){	
								connexion->username=datas->userid;
							}
							connexion->user_id=datas->uid;
							connexion->user_groups = datas->groups;
							connexion->sysname=datas->sysname;
							connexion->release=datas->release;
							connexion->version=datas->version;
							if (connexion->user_groups == NULL) {
								if ((header->option == 0x1) && multiclient_ok) {
									if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
										g_message("Get users info");
									/* group is not fill in multi users mode
									 * need to be done now */
									if ( nuauth_user_cache ){
										get_users_from_cache(connexion);
									} else {
										if ((*module_user_check)(connexion->username,NULL,0,&(connexion->user_id),&(connexion->user_groups))!=SASL_OK){
											if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_PACKET)){
												g_message("User not found");
											}

										}
									}
								} else {
									if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
										g_message("User_check return is bad");
									free_connection(connexion);
									return NULL;
								}
							}
							/* first reset timestamp to now */
							connexion->timestamp=time(NULL);
							connexion->state=STATE_USERPCKT;
							/* acl part is NULL */
							connexion->packet_id=NULL;
							connexion->acl_groups=NULL;

							/* Tadaaa */
							return connexion;
						}
						break;
					default:
						free_buffer_read(datas);
						if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER)){
							g_message("unsupported message type");
						}
				}
			}
			return NULL;
		default:
			free_buffer_read(datas);
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
				g_message("unsupported protocol");


	}
}
