/*
 ** Copyright(C) 2004 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

#include <ident.h>

/**
 * \todo conf read for timeout
 */

/**
 * ident check of user. 
 *
 */

  G_MODULE_EXPORT 
gchar* ip_authentication(tracking* ipheader)
{
  struct in_addr laddr, faddr;
  struct timeval timeout;
  char *identifier, *opsys, *charset;
  char* username=NULL;
  ident_t * id=NULL;
  int lport=ipheader->dest ;
  int fport=ipheader->source ;
  int rcode;

  laddr.s_addr=INADDR_ANY ; //htonl(ipheader->daddr);
  faddr.s_addr=htonl(ipheader->saddr);


  timeout.tv_sec=3;
  timeout.tv_usec=300;

  id = id_open(&laddr, &faddr, &timeout);
  if (id){
      if (id_query(id, fport, lport , NULL)>0){
#ifdef DEBUG_ENABLE
              if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                         g_message("identd server sent some bytes");
#endif
          while((rcode= id_parse(id, &timeout, &fport, &lport, &identifier,
                  &opsys, &charset)) == 0);
          switch(rcode){
            case 1:
#ifdef DEBUG_ENABLE
              if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                  g_message("found username %s",identifier);
#endif
              username = identifier; 
	      g_free(opsys);
	      g_free(charset);
              break;
            case 2:
              if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                  g_message("protocol error");
              break;
            default:
              if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                  g_message("Unknown error (timeout ?)");

          }
      }
      id_close(id);
  } else {
	  int tmperrno=errno;
#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
          g_message("can not open ident to %s: %s",inet_ntoa(faddr),strerror(tmperrno));
#endif
  }
  return username; 
}
