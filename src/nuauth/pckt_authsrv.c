/*
 ** Copyright(C) 2003-2004 Eric Leblond <regit@inl.fr>
 **                        INL http://www.inl.fr/
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

#include <auth_srv.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> 

#include <errno.h>

/** 
 *fill ip related part of the connexion tracking header.
 * 
 * - Argument 1 : a connection
 * - Argument 2 : pointer to packet datas
 * - Return : offset to next type of headers 
 */

int get_ip_headers(connection *connexion,char * dgram)
{
	struct iphdr * iphdrs = (struct iphdr *) dgram;
	/* check IP version */
	if (iphdrs->version == 4){
#ifdef WORDS_BIGENDIAN	
		connexion->tracking_hdrs.saddr=(iphdrs->saddr);
		connexion->tracking_hdrs.daddr=(iphdrs->daddr);
#else
		connexion->tracking_hdrs.saddr=htonl(iphdrs->saddr);
		connexion->tracking_hdrs.daddr=htonl(iphdrs->daddr);
#endif
		/* get protocol */
		connexion->tracking_hdrs.protocol=iphdrs->protocol;
		return 4*iphdrs->ihl;
	}
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)){
		g_message("IP version is %d, ihl : %d",iphdrs->version,iphdrs->ihl);
	}
#endif
	return 0;
}

/** 
 * fill udp related part of the connexion tracking header.
 * 
 * - Argument 1 : a connection
 * - Argument 2 : pointer to packet datas
 * - Return : 0
 */

int get_udp_headers(connection *connexion, char * dgram)
{
	struct udphdr * udphdrs=(struct udphdr *)dgram;
#ifdef WORDS_BIGENDIAN	
	connexion->tracking_hdrs.source=(udphdrs->source);
	connexion->tracking_hdrs.dest=(udphdrs->dest);
#else
	connexion->tracking_hdrs.source=htons(udphdrs->source);
	connexion->tracking_hdrs.dest=htons(udphdrs->dest);
#endif
	connexion->tracking_hdrs.type=0;
	connexion->tracking_hdrs.code=0;
	return 0;
}


/**
 * fill tcp related part of the connexion tracking header.
 *
 * - Argument 1 : a connection
 * - Argument 2 : pointer to packet datas
 * - Return : STATE of the packet
 */

int get_tcp_headers(connection *connexion, char * dgram)
{
	struct tcphdr * tcphdrs=(struct tcphdr *) dgram;
#ifdef WORDS_BIGENDIAN	
	connexion->tracking_hdrs.source=(tcphdrs->source);
	connexion->tracking_hdrs.dest=(tcphdrs->dest);
#else
	connexion->tracking_hdrs.source=htons(tcphdrs->source);
	connexion->tracking_hdrs.dest=htons(tcphdrs->dest);
#endif

	connexion->tracking_hdrs.type=0;
	connexion->tracking_hdrs.code=0;
	/* test if fin ack or syn */
	/* if fin ack return 0 end of connection */
	if (tcphdrs->fin || tcphdrs->rst )
		return STATE_CLOSE;
	/* if syn return 1 */
	if (tcphdrs->syn) {
		if (tcphdrs->ack){
			return STATE_ESTABLISHED;
		} else {
			return STATE_OPEN;
		}
	}
	return -1;
}

/** 
 * fill icmp related part of the connexion tracking header.
 * 
 * - Argument 1 : a connection
 * - Argument 2 : pointer to packet datas
 * - Return : 0
 */


int get_icmp_headers(connection *connexion, char * dgram)
{
	struct icmphdr * icmphdrs= (struct icmphdr *)dgram;
	connexion->tracking_hdrs.source=0;
	connexion->tracking_hdrs.dest=0;
	connexion->tracking_hdrs.type=icmphdrs->type;
	connexion->tracking_hdrs.code=icmphdrs->code;
	return 0;
}

/**
 * decode a dgram packet from gateway and create a connection with it.
 * 
 * - Argument 1 : pointer to dgram
 * - Argument 2 : dgram size
 * - Return : pointer to allocated connection
 */

connection*  authpckt_decode(char * dgram, int  dgramsiz)
{
	int offset; 
	int8_t *pointer;
	uint8_t msg_type;
	uint16_t data_len;

#ifdef WORDS_BIGENDIAN	
	uint32_t tmpdata;
#endif
	connection*  connexion = NULL;

	switch (*dgram) {
		case 0x1:
			msg_type=*(dgram+1);
			if ( (msg_type == AUTH_REQUEST) || (msg_type == AUTH_CONTROL) ) {
				/* allocate connection */
				connexion = g_new0( connection,1);
				if (connexion == NULL){
					if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
						g_message("Can not allocate connexion\n");
					}
					return NULL;
				}
				/* parse packet */
				pointer=(int8_t*)dgram + 2;


				data_len=*(uint16_t *)pointer;
#ifdef WORDS_BIGENDIAN	
				data_len=swap16(data_len);
#endif
				if (data_len != dgramsiz){
					if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
						g_warning("packet seems to contain other datas, left %d byte(s) (announced : %d, get : %d)",
								dgramsiz-data_len,
								data_len,
								dgramsiz);
					}
				}
				pointer+=2;
				connexion->acl_groups=NULL;
				connexion->user_groups=NULL;
				connexion->packet_id=NULL;
#ifdef WORDS_BIGENDIAN	
				tmpdata=swap32(*(uint32_t * )pointer);
				connexion->packet_id=g_slist_append(connexion->packet_id, GUINT_TO_POINTER(tmpdata));
#else
				connexion->packet_id=g_slist_append(connexion->packet_id, GUINT_TO_POINTER(*(uint32_t * )pointer));
#endif
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)) {
					g_message("Working on  %u\n",(uint32_t)GPOINTER_TO_UINT(connexion->packet_id->data));
				}
#endif
				pointer+=sizeof (uint32_t);

#ifdef WORDS_BIGENDIAN	
				connexion->timestamp=swap32(*(uint32_t * )pointer);
#else
				connexion->timestamp=*( int32_t * )(pointer);
#endif
				pointer+=sizeof ( int32_t);
				/* get ip headers till tracking is filled */
				offset = get_ip_headers(connexion, (char*)pointer);
				if ( offset) {
					pointer+=offset;
					/* get saddr and daddr */
					/* check if proto is in Hello mode list (when hello authentication is used) */
					if ( nuauthconf->hello_authentication &&  localid_authenticated_protocol(connexion->tracking_hdrs.protocol) ) {
						connexion->state=STATE_HELLOMODE;
					} 
					switch (connexion->tracking_hdrs.protocol) {
						case IPPROTO_TCP:
							switch (get_tcp_headers(connexion, (char*)pointer)){
								case STATE_OPEN:
									break; 
								case STATE_CLOSE:
									if (msg_type == AUTH_CONTROL ){
										log_user_packet(*connexion,STATE_CLOSE);
										return NULL;
									}
									break;
								case STATE_ESTABLISHED:
									if (msg_type == AUTH_CONTROL ){
										log_user_packet(*connexion,STATE_ESTABLISHED);
										return NULL;
									}
									break;
								default:
									if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
										g_warning ("Can't parse TCP headers\n");
									free_connection(connexion);
									return NULL;
							}
							break;
						case IPPROTO_UDP:
							if ( get_udp_headers(connexion, (char*)pointer) ){
								if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
									g_warning ("Can't parse UDP headers\n");
								free_connection(connexion);
								return NULL;
							}
							break;
						case IPPROTO_ICMP:
							if ( get_icmp_headers(connexion, (char*)pointer)){
								if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
									g_message ("Can't parse ICMP headers\n");
								free_connection(connexion);
								return NULL;
							}
							break;
						default:
							if ( connexion->state != STATE_HELLOMODE){
								if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
									g_message ("Can't parse this protocol\n");
								free_connection(connexion);
								return NULL;
							}
					}
				}
				else {
					if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
						g_message ("Can't parse IP headers\n");
					free_connection(connexion);
					return NULL;
				}
				connexion->user_groups = ALLGROUP;
				/* have look at timestamp */
				if ( connexion->timestamp == 0 ){
					connexion->timestamp=time(NULL);
				}
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)){
					g_message("Packet : ");
					print_connection(connexion,NULL);
				}
#endif
				return connexion;
			} else {

#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)) {
					g_message("Not for us\n");
				}
#endif
				return NULL;
			}
	}
	return NULL;
}



