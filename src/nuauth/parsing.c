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

/** \addtogroup NuauthCore
 * @{
 */

/*
 * Parse a string containing a list of addresses (separated by spaces).
 * Skip invalid addresses.
 *
 * \return Returns an array of in_addr, or NULL if no valid address has been found.
 * The array always finish with an INADDR_NONE value.
 */
struct in6_addr* generate_inaddr_list(gchar* gwsrv_addr)
{
    gchar** gwsrv_addr_list=NULL;
    gchar** iter=NULL ;
    struct in6_addr *authorized_server=NULL;
    struct in6_addr *addrs_array=NULL;
    struct in6_addr addr6;
    struct in_addr addr4;
    unsigned int count = 0;

    if (gwsrv_addr == NULL)
        return NULL;

    /* parse nufw server address */
    gwsrv_addr_list = g_strsplit(gwsrv_addr ," ",0);

    /* compute array length */
    for (iter = gwsrv_addr_list; *iter != NULL; iter++)
    {
        if (0 < inet_pton(AF_INET6, *iter, &addr6)
         || 0 < inet_pton(AF_INET, *iter, &addr4))
        {
            count++;
        }
    }

    /* allocate array of struct sock_addr */
    if (0 < count)
    {
        addrs_array=g_new0(struct in6_addr, count+1);
        authorized_server=addrs_array;
        for (iter = gwsrv_addr_list; *iter != NULL; iter++)
        {
            if (0 < inet_pton(AF_INET6, *iter, &addr6)) {
                *authorized_server = addr6;
                authorized_server++;
            } else if (0 < inet_pton(AF_INET, *iter, &addr4)) {
                authorized_server->s6_addr32[0] = 0;
                authorized_server->s6_addr32[1] = 0;
                authorized_server->s6_addr32[2] = 0xffff0000;
                authorized_server->s6_addr32[3] = addr4.s_addr;
                authorized_server++;
            }

        }
        *authorized_server = in6addr_any;
    }
    g_strfreev(gwsrv_addr_list);
    return addrs_array;
}


gboolean check_inaddr_in_array(struct in6_addr *check_ip, struct in6_addr *iparray)
{
    struct in6_addr *ipitem;
    /* test if server is in the list of authorized servers */
    if (iparray){
        ipitem=iparray;
        while (memcmp(ipitem, &in6addr_any, sizeof(*ipitem)) != 0)
        {
            if (memcmp(ipitem, check_ip, sizeof(*ipitem)) == 0)
                return TRUE;
            ipitem++;
        }
    }
    return FALSE;
}

gboolean check_string_in_array(gchar* checkstring,gchar** stringarray)
{
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
        traduc = g_locale_from_utf8  (orig, -1, NULL, &bwritten, NULL);
        if (!traduc){
            log_message(WARNING, AREA_PACKET, "UTF-8 conversion failed at %s:%d",__FILE__,__LINE__);
            return NULL;
        }
    } else {
        traduc = orig;
    }

#define VALID_CHARS """@#$%^&*()_+1234567890-={}[]:,.<>/?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ "
    traduc = g_strcanon(traduc,VALID_CHARS,'_');
    orig = g_strescape(traduc,"");
    return orig;
}

/** @} */
