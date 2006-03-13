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

/*
 * Parse a string containing a list of addresses (separated by spaces).
 * Skip invalid addresses.
 * 
 * \return Returns an array of in_addr, or NULL if no valid address has been found.
 */
struct in_addr* generate_inaddr_list(gchar* gwsrv_addr)
{
	gchar** gwsrv_addr_list=NULL;
	gchar** gwsrv_addr_iter=NULL ;
	struct in_addr *authorized_server=NULL;
	struct in_addr *addrs_array=NULL;
	struct in_addr tmp_addr;
    unsigned int count = 0;
    
	if (gwsrv_addr == NULL)
        return NULL;
    
    /* parse nufw server address */
    gwsrv_addr_list = g_strsplit(gwsrv_addr ," ",0);

    /* compute array length */
    gwsrv_addr_iter = gwsrv_addr_list;
    while(*gwsrv_addr_iter){
        tmp_addr.s_addr = inet_addr(*gwsrv_addr_iter);
        if (tmp_addr.s_addr != INADDR_NONE) {
            gwsrv_addr_iter++;
            count++;
        }
    }
    
    /* allocate array of struct sock_addr */
    if (0 < count)
    {
        addrs_array=g_new0(struct in_addr, count+1);
        authorized_server=addrs_array;
        gwsrv_addr_iter = gwsrv_addr_list;
        while (*gwsrv_addr_iter != NULL) {
            tmp_addr.s_addr = inet_addr(*gwsrv_addr_iter);
            if (tmp_addr.s_addr != INADDR_NONE) {
                *authorized_server = tmp_addr;
                authorized_server++;
                gwsrv_addr_iter++;
            }
        }
        authorized_server->s_addr=INADDR_NONE;
    }
    g_strfreev(gwsrv_addr_list);
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

gchar *string_escape(gchar *orig)
{
	gchar * traduc;
	/* convert from utf-8 to locale if needed */
	if (nuauthconf->uses_utf8){
		size_t bwritten;
		traduc = g_locale_from_utf8  (orig,
                                          -1,
                                           NULL,
                                           &bwritten,
                                           NULL);
                if (!traduc){
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
                        g_warning("UTF-8 conversion failed at %s:%d",__FILE__,__LINE__);
                    }
                    return NULL;
                }
	} else {
		traduc = orig;
	}

#define VALID_CHARS """@#$%^&*()_+1234567890-={}[]:,.<>/?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ "
        traduc=g_strcanon(traduc,VALID_CHARS,'_');
	orig = g_strescape(traduc,"");
	return orig;
}


