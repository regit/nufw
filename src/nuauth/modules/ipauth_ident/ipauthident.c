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

/**
 *
 * \ingroup AuthNuauthModules
 * \defgroup IPauthModule Ident authentication module
 * \brief This module authenticates user by doing an ident request
 *
 * \warning This is a proof of concept. Do not use it in production environnement.
 *
 * @{ */



#include <auth_srv.h>

#include <ident.h>

/**
 * ident check of user. 
 *
 * \param ipheader Pointer to the IP parameter of the packet to authenticate
 * \param params Pointer to module instance parameters
 * \return The "assumed" name of the user which has sent the packet 
 */

  G_MODULE_EXPORT 
gchar* ip_authentication(tracking_t* ipheader,gpointer params)
{
  struct in_addr laddr, faddr;
  struct timeval timeout;
  char *identifier, *opsys, *charset;
  char* username=NULL;
  ident_t * id=NULL;
  int lport=ipheader->dest ;
  int fport=ipheader->source ;
  int rcode;

  laddr.s_addr=INADDR_ANY ; /* htonl(ipheader->daddr); */
  faddr.s_addr=htonl(ipheader->saddr);


  timeout.tv_sec=3;
  timeout.tv_usec=300;

  id = id_open(&laddr, &faddr, &timeout);
  if (id){
      if (id_query(id, fport, lport , NULL)>0){
              debug_log_message(VERBOSE_DEBUG, AREA_USER, "identd server sent some bytes");
          while((rcode= id_parse(id, &timeout, &fport, &lport, &identifier,
                  &opsys, &charset)) == 0);
          switch(rcode){
            case 1:
              debug_log_message(VERBOSE_DEBUG, AREA_USER, "found username %s",identifier);
              username = identifier; 
	      g_free(opsys);
	      g_free(charset);
              break;
            case 2:
              log_message(VERBOSE_DEBUG, AREA_USER, "protocol error");
              break;
            default:
              log_message(VERBOSE_DEBUG, AREA_USER, "Unknown error (timeout ?)");

          }
      }
      id_close(id);
  } else {
#ifdef DEBUG_ENABLE
      int tmperrno=errno;
      log_message(DEBUG, AREA_USER, "can not open ident to %s: %s",inet_ntoa(faddr),strerror(tmperrno));
#endif
  }
  return username; 
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
  return TRUE;
}

/** @} */
