/*
 ** Copyright(C) INL 2005 
 ** written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
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
 **
 */


#include <auth_srv.h>


struct in_addr* generate_inaddr_list(gchar* gwsrv_addr)
{
	gchar** gwsrv_addr_list=NULL;
	gchar** gwsrv_addr_item=NULL ;
	struct in_addr *authorized_server=NULL;
	struct in_addr *addrs_array=NULL;
	if (gwsrv_addr){
		/* parse nufw server address */
		gwsrv_addr_list = g_strsplit(gwsrv_addr ," ",0);
		gwsrv_addr_item = gwsrv_addr_list;
		/* compute array length */
		while(*gwsrv_addr_item)
			gwsrv_addr_item++;
		/* allocate array of struct sock_addr */
		addrs_array=g_new0(struct in_addr,gwsrv_addr_item-gwsrv_addr_list );
		authorized_server=addrs_array;
		gwsrv_addr_item = gwsrv_addr_list;
		while(*gwsrv_addr_item){
			authorized_server->s_addr=inet_addr(*gwsrv_addr_item);
			authorized_server++;
			gwsrv_addr_item++;
		}
		authorized_server->s_addr=INADDR_NONE;
		g_strfreev(gwsrv_addr_list);
	}
	return addrs_array;
}


gboolean check_inaddr_in_array(struct in_addr check_ip,struct in_addr *iparray){
	struct in_addr *ipitem;
	/* test if server is in the list of authorized servers */
	if (iparray){
		ipitem=iparray;
		while(ipitem->s_addr != INADDR_NONE){
			if ( ipitem->s_addr == check_ip.s_addr )
				return TRUE;
			ipitem++;
		} 
	}
	return FALSE;
}

gboolean check_string_in_array(gchar* checkstring,gchar** stringarray){
	gchar **stringitem;
	/* test if server is in the list of authorized servers */
	if (stringarray){
		stringitem=stringarray;
		while(*stringitem){
			if ( !strcmp(*stringitem,checkstring))
				return TRUE;
			stringitem++;
		} 
	}
	return FALSE;

}

