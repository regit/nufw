
/*
 **  "plaintext" module
 ** Copyright(C) 2004-2005 Mikael Berthe <mikael+nufw@lists.lilotux.net>
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

#include "auth_srv.h"
#include <string.h>
#include "auth_plaintext.h"

/**
 * strip_line()
 * Returns a pointer on stripped line or
 * NULL if the line should be skipped and acceptnull is true.
 */
char *strip_line(char *line, int acceptnull)
{
  char *p_tmp;

  /*  Let's get rid of tabs and spaces */
  while ((*line == 32) || (*line == 9))
      line++;
  /*  Let's get rid of trailing characters */
  for (p_tmp = line; *p_tmp; p_tmp++)
      ;
  if (p_tmp != line)
      p_tmp--;
  for ( ; p_tmp>line && (*p_tmp=='\x0a' || *p_tmp=='\x0d' ||
              *p_tmp==32 || *p_tmp==9); *p_tmp-- = 0)
      ;

  if (!acceptnull)
      return line;

  /*  Discard comments and empty lines */
  if (*line == '#' || *line == 0 ||
          *line == '\x0d' || *line == '\x0a')
      return NULL;

  return line;
}

/**
 * parse_ints()
 * Extracts integers (like group ids) in intline and fills *p_intlist.
 * prefix is displayed in front of the log messages.
 * Returns 0 if successful.
 */
int parse_ints(char *intline, GSList **p_intlist, char *prefix)
{
  char *p_nextint;
  char *p_ints = intline;
  GSList *intlist = *p_intlist;
  int number;

  /*  parsing ints */
  while (p_ints) {
      p_nextint = strchr(p_ints, ',');
      if (p_nextint) {
          *p_nextint = 0;
      }
      if (sscanf(p_ints, "%u", &number) != 1) {
          /*  We can't read a number.  This will be an error only if we can */
          /*   see a comma next. */
          if (p_nextint) {
              log_message(WARNING, AREA_MAIN,
                      "%s parse_ints: Malformed line", prefix);
              *p_intlist = intlist;
              return 1;
          }
          log_message(WARNING, AREA_MAIN,
                  "%s parse_ints: Garbarge at end of line", prefix);
      } else {
          /*  One number (group, integer...) to add */
          intlist = g_slist_prepend(intlist,
                  GINT_TO_POINTER((u_int32_t)number));
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "%s Added group/int %d", prefix, number);
      }
      if ((p_ints = p_nextint))
          p_ints++;
  }

  *p_intlist = intlist;
  return 0;
}

/**
 * parse_ports()
 * Extracts ports from groupline and fills *p_portslist.
 * prefix is displayed in front of the log messages.
 * Returns 0 if successful.
 */
int parse_ports(char *portsline, GSList **p_portslist, char *prefix)
{
  char *p_nextports;
  char *p_ports = portsline;
  GSList *portslist = *p_portslist;
  struct T_ports ports;
  int n, fport, lastport;

  /*  parsing ports */
  while (p_ports) {
      p_nextports = strchr(p_ports, ',');
      if (p_nextports) {
          *p_nextports = 0;
      }
      n = sscanf(p_ports, "%d-%d", &fport, &lastport);
      ports.firstport = (uint16_t) fport;
      if ((n != 1) && (n != 2)) {
          /*  We can't read a port number.  This will be an error only if we can */
          /*   see a comma next. */
          if (p_nextports) {
              log_message(WARNING, AREA_MAIN,
                      "%s parse_ports: Malformed line", prefix);
              *p_portslist = portslist;
              return 1;
          }
          log_message(WARNING, AREA_MAIN,
                  "%s parse_ports: Garbarge at end of line", prefix);
      } else {
          struct T_ports *this_port;
          /*  One port or ports range to add... */
          if (n == 2) {  /*  That's a range */
              if (lastport >= fport) {
                  ports.nbports = lastport - fport;
              } else {
                  ports.nbports = -1;
                  log_message(WARNING, AREA_MAIN,
                          "%s parse_ports: Malformed line", prefix);
              }
          } else
              ports.nbports = 0;

          if (ports.nbports >= 0) {
              this_port = g_new0(struct T_ports, 1);
              this_port->firstport = ports.firstport;
              this_port->nbports = ports.nbports;
              portslist = g_slist_prepend(portslist, this_port);
              debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                      "%s Adding Port = %d, number = %d", prefix,
                      ports.firstport, ports.nbports);
          }
      }
      if ((p_ports = p_nextports))
          p_ports++;
  }

  *p_portslist = portslist;
  return 0;
}

/**
 * parse_ips()
 * Extracts IP addresses from ipsline and fills *p_ipslist.
 * prefix is displayed in front of the log messages.
 * Returns 0 if successful.
 */
int parse_ips(char *ipsline, GSList **p_ipslist, char *prefix)
{
  char *p_nextip;
  char *p_ip = ipsline;
  GSList *ipslist = *p_ipslist;
  struct in_addr ip_addr;
  uint32_t *p_address, *p_netmask;
  char *p_tmp;

  /*  parsing IPs */
  /*  XXX only IPv4 for now */
  while (p_ip) {
      int n = 1;
      uint32_t mask = 0;
      int imask = 0;

      p_nextip = strchr(p_ip, ',');
      if (p_nextip) {
          *p_nextip = 0;
      }

      p_ip = strip_line(p_ip, FALSE);
      /*  Is there a netmask? */
      p_tmp = strchr(p_ip, '/');
      if (p_tmp) {
          *p_tmp++ = 0;
          n = sscanf(p_tmp, "%d", &imask);
          mask = (uint32_t) imask;
      } else    /*  no -> default netmask is 32 bits */
          mask = 32;

      if ((n != 1) || (inet_pton(AF_INET, p_ip, &ip_addr) <= 0)) {
          /*  We can't read an IP address.  This will be an error only if we can */
          /*   see a comma next. */
          if (p_nextip) {
              log_message(WARNING, AREA_MAIN,
                      "%s parse_ips: Malformed line", prefix);
              *p_ipslist = ipslist;
              return 1;
          }
          log_message(WARNING, AREA_MAIN,
                  "%s parse_ips: Garbarge at end of line", prefix);
      } else {
          struct T_ip *this_ip = g_new0(struct T_ip, 1);
          this_ip->addr.s_addr = ip_addr.s_addr;
          this_ip->netmask.s_addr = 0; 

          /*  Netmask conversion */
          p_netmask = (uint32_t *)&this_ip->netmask.s_addr;
          for (n = 0 ; n < (int)mask ; n++) {
              *p_netmask <<= 1;
              *p_netmask |= 1;
          }

          p_address = (uint32_t *)&this_ip->addr.s_addr;

          if ((*p_address & *p_netmask) != *p_address) {
              log_message(WARNING, AREA_MAIN,
                      "%s parse_ips: Invalid network specification!",
                      prefix);
              *p_address &= *p_netmask;
          }

          ipslist = g_slist_prepend(ipslist, this_ip);

          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "%s Adding IP = %u, netmask = %u", prefix,
                  this_ip->addr.s_addr, this_ip->netmask.s_addr);
      }
      if ((p_ip = p_nextip))
          p_ip++;
  }

  *p_ipslist = ipslist;
  return 0;
}

/**
 * read_user_list()
 * Reads users conf file and fills the *plaintext_userlist structure.
 * Returns 0 if successful.
 * Line format: "username:passwd:gid1,gid2,gid3" (gid are numbers)
 */
int read_user_list(struct plaintext_params* params)
{
  struct T_plaintext_user *plaintext_user;
  FILE *fd;
  char line[1024];
  char *p_username, *p_passwd, *p_uid, *p_groups;
  u_int32_t uid;
  char log_prefix[16];
  int ln = 0;   /*  Line number */

  log_message(VERBOSE_DEBUG, AREA_AUTH,
          "[plaintext] read_user_list: reading [%s]", params->plaintext_userfile);

  fd = fopen(params->plaintext_userfile, "r");

  if (!fd) {
      log_message(WARNING, AREA_AUTH, "read_user_list: fopen error");
      return 1;
  }

  while (fgets(line, sizeof(line), fd) != NULL) {
      ln++;
      p_username = strip_line(line, TRUE);

      if (!p_username)
          continue;
      /*  TODO: check for bad characters */

      /*  User Name */
      if (!p_username) {
          log_message(WARNING, AREA_AUTH,
                  "L.%d: read_user_list: Malformed line (no username)", ln);
          fclose(fd);
          return 2;
      }

      /*  Password */
      p_passwd = strchr(p_username, ':');
      if (!p_passwd) {
          log_message(WARNING, AREA_AUTH,
                  "L.%d: read_user_list: Malformed line (no passwd)", ln);
          fclose(fd);
          return 2;
      }
      *p_passwd++ = 0;

      /*  UID */
      p_uid = strchr(p_passwd, ':');
      if (!p_uid) {
          log_message(WARNING, AREA_AUTH,
                  "L.%d: read_user_list: Malformed line (no uid)", ln);
          fclose(fd);
          return 2;
      }
      *p_uid++ = 0;
      if (sscanf(p_uid, "%d", &uid) != 1) {
          log_message(WARNING, AREA_AUTH,
                  "L.%d: read_user_list: Malformed line "
                  "(uid should be a number)", ln);
          fclose(fd);
          return 2;
      }

      /*  List of groups */
      p_groups = strchr(p_uid, ':');
      if (!p_groups) {
          log_message(WARNING, AREA_AUTH,
                  "L.%d: read_user_list: Malformed line (no groups)", ln);
          fclose(fd);
          return 2;
      }
      *p_groups++ = 0;

      debug_log_message(VERBOSE_DEBUG, AREA_AUTH,
              "L.%d: Read username=[%s], uid=%d",
              ln, p_username, uid);

      /*  Let's create an user node */
      plaintext_user = g_new0(struct T_plaintext_user, 1);
      if (!plaintext_user) {
          log_message(WARNING, AREA_AUTH,
                  "read_user_list: Cannot allocate T_plaintext_user!");
          fclose(fd);
          return 5;
      }
      plaintext_user->groups = NULL;
      plaintext_user->passwd = g_strdup(p_passwd);
      plaintext_user->username = g_strdup(p_username);
      plaintext_user->uid = uid;

      snprintf(log_prefix, sizeof(log_prefix)-1, "L.%d: ", ln);
      /*  parsing groups */
      if (parse_ints(p_groups, &plaintext_user->groups, log_prefix)) {
          g_free(plaintext_user);
          fclose(fd);
          return 2;
      }

      /*  User node is ready */
      params->plaintext_userlist = g_slist_prepend(params->plaintext_userlist, plaintext_user);
  }

  fclose(fd);

  return 0;
}

/**
 * read_acl_list()
 * Reads acls conf file and fills the *plaintext_acllist structure.
 * Returns 0 if successful.
 *
 * ACL begins with "[ACL name]", then each line should have the structure
 * "key = value".  For example "proto = 6".
 */
int read_acl_list(struct plaintext_params* params)
{
  FILE *fd;
  char line[1024];
  char *p_key, *p_value, *p_tmp;
  struct T_plaintext_acl *newacl = NULL;
  int ln = 0;   /*  Line number */

  log_message(VERBOSE_DEBUG, AREA_MAIN,
          "[plaintext] read_acl_list: reading [%s]", params->plaintext_aclfile);

  fd = fopen(params->plaintext_aclfile, "r");

  if (!fd) {
      log_message(WARNING, AREA_MAIN, "read_acl_list: fopen error");
      return 1;
  }

  while (fgets(line, 1000, fd)) {
      ln++;
      p_key = strip_line(line, TRUE);

      if (!p_key)
          continue;

      /*  New ACL? */
      if (p_key[0] == '[') {
          if (newacl) {
              debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                      "Done with ACL [%s]", newacl->aclname);
              /*  check if ACL node has minimal information */
              /*  Warning: this code is duplicated after the loop */
              if (!newacl->groups) {
                  log_message(WARNING, AREA_MAIN,
                          "No group(s) declared in ACL %s",
                          newacl->aclname);
              } else if (newacl->proto == IPPROTO_TCP ||
                      newacl->proto == IPPROTO_UDP ||
                      newacl->proto == IPPROTO_ICMP) {
                  /*  ACL node is ready */
                  params->plaintext_acllist = g_slist_prepend(params->plaintext_acllist, newacl);
              } else {
                  log_message(WARNING, AREA_MAIN,
                          "No valid protocol declared in ACL %s",
                          newacl->aclname);
              }
          }

          debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "L.%d: New ACL", ln);

          p_tmp = strchr(++p_key, ']');
          if (!p_tmp) {
              log_message(WARNING, AREA_MAIN,
                      "L.%d: Malformed line (ACLname)", ln);
              fclose(fd);
              return 2;
          }
          *p_tmp = 0;
          /*  Ok, new ACL declaration here.  Let's allocate a structure! */
          newacl = g_new0(struct T_plaintext_acl, 1);
          if (!newacl) {
              log_message(WARNING, AREA_MAIN,
                      "read_acl_list: Cannot allocate T_plaintext_acl!");
              fclose(fd);
              return 5;
          }

          newacl->aclname = g_strdup(p_key);
          newacl->period=NULL;
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "L.%d: ACL name found: [%s]", ln, newacl->aclname);
          /*  We're done with this line */
          continue;
      }

      /*  We shouldn't be here if we aren't in an ACL declaration */
      if (!newacl) {
          log_message(WARNING, AREA_MAIN,
                  "L.%d: Malformed line (Not in an ACL declaration)", ln);
          fclose(fd);
          return 2;
      }

      p_value = strchr(p_key, '=');
      if (!p_value) {
          log_message(WARNING, AREA_MAIN,
                  "L.%d: Malformed line (No '=' inside)", ln);
          fclose(fd);
          return 2;
      }
      *p_value++ = 0;

      p_key   = strip_line(p_key, FALSE);
      p_value = strip_line(p_value, FALSE);

      /*  Ok.  Let's study the key/value we've found, now. */
      if (!strcasecmp("decision", p_key)) {                     /*  Decision */
          unsigned int decis = atoi(p_value);
          
          switch (decis){
              case DECISION_ACCEPT:
                  newacl->decision = DECISION_ACCEPT;
                  break;
              case DECISION_DROP:
                  newacl->decision = DECISION_DROP;
                  break;
              case DECISION_REJECT:
                  newacl->decision = DECISION_REJECT;
                  break;
              default:
                  {
                      log_message(WARNING, AREA_MAIN,
                              "L.%d: Malformed line (decision should be 0 or 1)",
                              ln);
                      fclose(fd);
                      return 2;
                  }
          }
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "L.%d: Read decision = %d", ln, newacl->decision);
      } else if (!strcasecmp("gid", p_key)) {                   /*  Groups */
          char log_prefix[16];
          snprintf(log_prefix, sizeof(log_prefix)-1, "L.%d: ", ln);
          /*  parsing groups */
          if (parse_ints(p_value, &newacl->groups, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("proto", p_key)) {                 /*  Protocol */
          if (sscanf(p_value, "%d", &newacl->proto) != 1) {
              log_message(WARNING, AREA_MAIN,
                      "L.%d: Malformed line (proto should be a number)",
                      ln);
              fclose(fd);
              return 2;
          }
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "L.%d: Read proto = %d", ln, newacl->proto);
      } else if (!strcasecmp("type", p_key)) {                  /*  Type (icmp) */
          char log_prefix[16];
          snprintf(log_prefix, sizeof(log_prefix)-1, "L.%d: ", ln);
          /*  parse type values */
          if (parse_ints(p_value, &newacl->types, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("srcip", p_key)) {                 /*  SrcIP */
          char log_prefix[16];
          snprintf(log_prefix, sizeof(log_prefix)-1, "L.%d: ", ln);
          /*  parsing IPs */
          if (parse_ips(p_value, &newacl->src_ip, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("srcport", p_key)) {               /*  SrcPort */
          char log_prefix[16];
          snprintf(log_prefix, sizeof(log_prefix)-1, "L.%d: ", ln);
          /*  parsing ports */
          if (parse_ports(p_value, &newacl->src_ports, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("dstip", p_key)) {                 /*  DstIP */
          char log_prefix[16];
          snprintf(log_prefix, sizeof(log_prefix)-1, "L.%d: ", ln);
          /*  parsing IPs */
          if (parse_ips(p_value, &newacl->dst_ip, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("dstport", p_key)) {               /*  DstPort */
          char log_prefix[16];
          snprintf(log_prefix, sizeof(log_prefix)-1, "L.%d: ", ln);
          /*  parsing ports */
          if (parse_ports(p_value, &newacl->dst_ports, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("app", p_key)) {                   /*  App */
          char *sep;
          struct T_app *newapp = g_new0(struct T_app, 1);

          sep = strchr(p_value, ';');
          if (sep)
              *sep++ = 0;
          newapp->appname = g_strdup(strip_line(p_value, 0));
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "L.%d: Read App name [%s]", ln, newapp->appname);

          /*  MD5: */
          if (sep) {
              p_value = sep;
              newapp->appmd5 = g_strdup(strip_line(p_value, 0));
              debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                      "L.%d: Read App MD5 [%s]", ln, newapp->appmd5);
          }
          /*  TODO checks */
          newacl->apps = g_slist_prepend(newacl->apps, newapp);
      } else if (!strcasecmp("os", p_key)) {                    /*  OS */
          char *sep;
          struct T_os *newos = g_new0(struct T_os, 1);

          sep = strchr(p_value, ';');
          if (sep)
              *sep++ = 0;
          newos->sysname = g_strdup(strip_line(p_value, 0));
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "L.%d: Read OS sysname [%s]", ln, newos->sysname);

          /*  Release: */
          if (sep) {
              p_value = sep;
              sep = strchr(p_value, ';');
              if (sep)
                  *sep++ = 0;
              newos->release = g_strdup(strip_line(p_value, 0));
              debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                      "L.%d: Read OS release [%s]",
                      ln, newos->release);
          }
          /*  Version: */
          if (sep) {
              p_value = sep;
              newos->version = g_strdup(strip_line(p_value, 0));
              debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                      "L.%d: Read OS version [%s]",
                      ln, newos->version);
          }

          /*  TODO checks */
          newacl->os = g_slist_prepend(newacl->os, newos);
      } else if (!strcasecmp("period", p_key)) {                /*  Period */
          newacl->period = g_strdup(p_value);
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "L.%d: Read  period [%s]", ln, newacl->period);
      } else {
          log_message(SERIOUS_WARNING, AREA_MAIN,
                  "L.%d: Unknown key [%s] in ACL %s",
                  ln, p_key, newacl->aclname);
      } /*  End of key/value parsing */
  }
  if (newacl) {

      debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
              "Done with ACL [%s]", newacl->aclname);
      /*  check if ACL node has minimal information */
      /*  Warning: this code is duplicated after the loop */
      if (!newacl->groups) {
          log_message(WARNING, AREA_MAIN,
                  "No group(s) declared in ACL %s", newacl->aclname);
      } else if (newacl->proto == IPPROTO_TCP ||
              newacl->proto == IPPROTO_UDP ||
              newacl->proto == IPPROTO_ICMP) {
          /*  ACL node is ready */
          params->plaintext_acllist = g_slist_prepend(params->plaintext_acllist, newacl);
      } else {
          log_message(WARNING, AREA_MAIN,
                  "No valid protocol declared in ACL %s", newacl->aclname);
      }
  }

  fclose(fd);
  return 0;
}

G_MODULE_EXPORT gboolean module_params_unload(gpointer params_p)
{
  struct plaintext_params* params=(struct plaintext_params*)params_p;
  /*  Free user list */
  if (params){
      if (params->plaintext_userlist) {
          GSList *p_userlist;
          struct T_plaintext_user *p_user;

          debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "Freeing users list");

          /*  Let's free each node separately */
          for (p_userlist = params->plaintext_userlist ; p_userlist ;
                  p_userlist = g_slist_next(p_userlist)) {
              p_user = (struct T_plaintext_user*) p_userlist->data;
              g_free(p_user->passwd);
              g_free(p_user->username);
              if (p_user->groups)
                  g_slist_free(p_user->groups);
          }
          /*  Now we can free the list */
          g_slist_free(params->plaintext_userlist);
          params->plaintext_userlist = NULL;
      }

      /*  Free acl list */
      if (params->plaintext_acllist) {
          GSList *p_acllist;
          struct T_plaintext_acl *p_acl;

          debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "Freeing ACLs");

          /*  Let's free each node separately */
          for (p_acllist = params->plaintext_acllist ; p_acllist ;
                  p_acllist = g_slist_next(p_acllist)) {
              p_acl = (struct T_plaintext_acl*) p_acllist->data;
              g_free(p_acl->aclname);
              if (p_acl->groups)
                  g_slist_free(p_acl->groups);
              /*  Let's free each appname(/appmd5) */
              if (p_acl->apps) {
                  GSList *p_app = p_acl->apps;
                  for ( ; p_app ; p_app = g_slist_next(p_app)) {
                      /*  Free AppName string */
                      g_free(((struct T_app*)p_app->data)->appname);
                      /*  Free MD5 string if there is one */
                      if (((struct T_app*)p_app->data)->appmd5)
                          g_free(((struct T_app*)p_app->data)->appmd5);
                  }
                  g_slist_free(p_acl->apps);
              }
              /*  Free Src IPs */
              if (p_acl->src_ip)
                  g_slist_free(p_acl->src_ip);
              /*  Free Dst IPs */
              if (p_acl->dst_ip)
                  g_slist_free(p_acl->dst_ip);
              /*  Free Src ports */
              if (p_acl->src_ports)
                  g_slist_free(p_acl->src_ports);
              /*  Free Dst ports */
              if (p_acl->dst_ports)
                  g_slist_free(p_acl->dst_ports);
              g_free(p_acl);
          }
          /*  Now we can free the list */
          g_slist_free(params->plaintext_acllist);
          params->plaintext_acllist = NULL;
      }
  }
  g_free(params);
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
  gpointer vpointer;
  struct plaintext_params* params=g_new0(struct plaintext_params,1);
  confparams plaintext_nuauth_vars[] = {
      { "plaintext_userfile", G_TOKEN_STRING, 0, g_strdup(TEXT_USERFILE) },
      { "plaintext_aclfile",  G_TOKEN_STRING, 0, g_strdup(TEXT_ACLFILE) }
  };


  /*  parse conf file */
  if (module->configfile){
      parse_conffile(module->configfile,
              sizeof(plaintext_nuauth_vars)/sizeof(confparams),
              plaintext_nuauth_vars);
  } else {
      parse_conffile(DEFAULT_CONF_FILE,
              sizeof(plaintext_nuauth_vars)/sizeof(confparams),
              plaintext_nuauth_vars);
  }
  /*  set variables */
  vpointer = get_confvar_value(plaintext_nuauth_vars,
          sizeof(plaintext_nuauth_vars)/sizeof(confparams),
          "plaintext_userfile");
  params->plaintext_userfile = (char *)(vpointer?vpointer:params->plaintext_userfile);
  vpointer = get_confvar_value(plaintext_nuauth_vars,
          sizeof(plaintext_nuauth_vars)/sizeof(confparams),
          "plaintext_aclfile");
  params->plaintext_aclfile  = (char *)(vpointer?vpointer:params->plaintext_aclfile);
  params->plaintext_userlist = NULL;
  params->plaintext_acllist = NULL;

  /* free config struct */
  free_confparams(plaintext_nuauth_vars,sizeof(plaintext_nuauth_vars)/sizeof(confparams));
  
  module->params = (gpointer) params; 
  return TRUE;
}

/*  This function is used by g_slist_find_custom() in user_check(). */
gint find_by_username(struct T_plaintext_user *a, struct T_plaintext_user *b)
{
  return strcmp(a->username, b->username);
}


/**
 *  user_check()
 *  arg 1 : user name string
 *  arg 2 : user provided password
 *  arg 3 : password length
 *  arg 4 : pointer to user id
 *  arg 5 : pointer to user groups list
 *  return : SASL_OK if password is correct, other values are authentication
 *           failures
 *  modify : groups to return the list of user groups,
 *           uid to return the user id
 */
G_MODULE_EXPORT int user_check(const char *username, const char *clientpass,
        unsigned passlen, uint32_t* uid, GSList **groups,gpointer params)
{
  GSList *outelt = *groups;
  GSList *res;
  struct T_plaintext_user ref;
  char *realpass;
  int initstatus;
  char *user;
  static GStaticMutex plaintext_initmutex = G_STATIC_MUTEX_INIT;

  /* init has only to be done once */
  g_static_mutex_lock (&plaintext_initmutex);
  /*  Initialization if the user list is empty */
  if (!((struct plaintext_params*)params)->plaintext_userlist) {
      initstatus = read_user_list(params);
      if (initstatus) {
          log_message(SERIOUS_WARNING, AREA_AUTH,
                  "Can't parse users file [%s]",((struct plaintext_params*)params)->plaintext_userfile);
          return SASL_BADAUTH;
      }
  }
  g_static_mutex_unlock (&plaintext_initmutex);

  /* strip username from domain */
  user = get_rid_of_domain((char*)username);
  debug_log_message(VERBOSE_DEBUG, AREA_AUTH,
          "Looking for group(s) for user %s", user);
  /*  Let's look for the first node with matching username */
  ref.username = (char*)user;
  res = g_slist_find_custom(((struct plaintext_params*)params)->plaintext_userlist, &ref,
          (GCompareFunc)find_by_username);

  if (!res) {
      log_message(WARNING, AREA_AUTH, "Unknown user [%s]!", user);
      return SASL_BADAUTH;
  }

  realpass = ((struct T_plaintext_user*)res->data)->passwd;

  if (!strcmp(realpass, "*") || !strcmp(realpass, "!")) {
      log_message(INFO, AREA_AUTH,
              "user_check: Account is disabled (%s)", user);
      return SASL_BADAUTH;
  }

  /*  If both clientpass and passlen are null, we just need to */
  /*  return the groups list (no checks needed) */
  if (clientpass) {
      if (verify_user_password(clientpass, realpass) != SASL_OK ){
          log_message(INFO, AREA_AUTH,
                  "user_check: Wrong password for %s", user);
          return SASL_BADAUTH;
      }
  }

  outelt = g_slist_copy(((struct T_plaintext_user*)res->data)->groups);

  debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
          "We are leaving (plaintext) user_check()");

  *groups = outelt;
  *uid = ((struct T_plaintext_user*)res->data)->uid;

  return SASL_OK;
}

/*  acl_check() */
G_MODULE_EXPORT GSList* acl_check(connection_t* element,gpointer params)
{
  GSList *g_list = NULL;
  GSList *p_acllist;
  struct acl_group *this_acl;
  tracking_t *netdata = &element->tracking;
  struct T_plaintext_acl *p_acl;
  int initstatus;
  uint32_t src_ip, dst_ip;
  static GStaticMutex plaintext_initmutex = G_STATIC_MUTEX_INIT;
  time_t periodend = -1;

  /* init has only to be done once */
  g_static_mutex_lock (&plaintext_initmutex);
  /*  Initialization if the ACL list is empty */
  if (!((struct plaintext_params*)params)->plaintext_acllist) {
      initstatus = read_acl_list((struct plaintext_params*)params);
      if (initstatus) {
          log_message(SERIOUS_WARNING, AREA_MAIN,
                  "Can't parse ACLs file [%s]", ((struct plaintext_params*)params)->plaintext_aclfile);
          return NULL;
      }
  }
  g_static_mutex_unlock (&plaintext_initmutex);

  /*  netdata.protocol     IPPROTO_TCP || IPPROTO_UDP || IPPROTO_ICMP */
  /*  netdata.type         for ICMP */
  /*  netdata.code         for ICMP */
  /*  netdata.saddr        IP source */
  /*  netdata.daddr        IP destination */
  /*  netdata.source       Port source */
  /*  netdata.dest         Port destination */

  /* TODO check if ntohl is needed */
  src_ip = ntohl(netdata->saddr);
  dst_ip = ntohl(netdata->daddr); 

  for (p_acllist = ((struct plaintext_params*)params)->plaintext_acllist ; p_acllist ;
          p_acllist = g_slist_next(p_acllist)) {
      p_acl = (struct T_plaintext_acl*)p_acllist->data;

      if (netdata->protocol != p_acl->proto)
          continue;

      /*  Check source address */
      if (!p_acl->src_ip){
          continue;
      } else {
          int found = 0;
          struct T_ip *p_ip;
          GSList *pl_ip = p_acl->src_ip;
          for ( ; pl_ip ; pl_ip = g_slist_next(pl_ip)) {
              p_ip = (struct T_ip*)pl_ip->data;
              if ((src_ip & p_ip->netmask.s_addr) == p_ip->addr.s_addr) {
                  found = 1;
                  break;
              }
          }
          if (!found)
              continue; /*  We don't have a match */
      }
      /*  Check destination address */
      if (!p_acl->dst_ip){
          continue;
      } else {
          int found = 0;
          struct T_ip *p_ip;
          GSList *pl_ip = p_acl->dst_ip;
          for ( ; pl_ip ; pl_ip = g_slist_next(pl_ip)) {
              p_ip = (struct T_ip*)pl_ip->data;
              if ((dst_ip & p_ip->netmask.s_addr) == p_ip->addr.s_addr) {
                  found = 1;
                  break;
              }
          }
          if (!found)
              continue; /*  We don't have a match */
      }

      /*  ICMP? */
      if (netdata->protocol == IPPROTO_ICMP) {
          if (p_acl->proto == IPPROTO_ICMP){
              int found = 0;
              GSList *sl_type = p_acl->types;
              for ( ; sl_type ; sl_type = g_slist_next(sl_type)) {
                  if (*((int*)sl_type->data) == netdata->type) {
                      found = 1;
                      break;
                  }
              }
              if (!found)
                  continue;
          }
      } else {
          /*  Following is only for TCP / UDP  (ports stuff...) */
          if (p_acl->proto != IPPROTO_TCP && p_acl->proto != IPPROTO_UDP) {
              g_message("[plaintext] Unsupported protocol: %d", p_acl->proto);
              continue;
          }

          /*  Check source port */
          if (p_acl->src_ports) {
              int found = 0;
              struct T_ports *p_ports;
              GSList *pl_ports = p_acl->src_ports;
              for ( ; pl_ports ; pl_ports = g_slist_next(pl_ports)) {
                  p_ports = (struct T_ports*)pl_ports->data;
                  if (!p_ports->firstport ||
                          ((netdata->source >= p_ports->firstport) &&
                           (netdata->source <= p_ports->firstport+p_ports->nbports))) {
                      found = 1;
                      break;
                  }
              }
              if (!found)
                  continue;
          }
          /*  Check destination port */
          if (p_acl->dst_ports) {
              int found = 0;
              struct T_ports *p_ports;
              GSList *pl_ports = p_acl->dst_ports;
              for ( ; pl_ports ; pl_ports = g_slist_next(pl_ports)) {
                  p_ports = (struct T_ports*)pl_ports->data;
                  if (!p_ports->firstport ||
                          ((netdata->dest >= p_ports->firstport) &&
                           (netdata->dest <= p_ports->firstport+p_ports->nbports))) {
                      found = 1;
                      break;
                  }
              }
              if (!found){
                  continue;
              }
          }
      }


      /*  O.S. filtering? */
      debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
              "(DBG) current ACL os=%p", p_acl->os);

      if (element->os_sysname && p_acl->os) {
          GSList *p_os = p_acl->os;
          gchar *p_sysname, *p_release, *p_version;
          int found = 0;

          /*  sysname */
          log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "[plaintext] Checking for OS sysname=[%s]",
                  element->os_sysname);

          for ( ; p_os ; p_os = g_slist_next(p_os)) {
              p_sysname = ((struct T_os*)p_os->data)->sysname;
              p_release = ((struct T_os*)p_os->data)->release;
              p_version = ((struct T_os*)p_os->data)->version;
              if (!strcasecmp(p_sysname, element->os_sysname)) {
                  if (element->os_release && p_release) {
                      if (!strcasecmp(p_release, element->os_release)) {
                          if (element->os_version && p_version) {
                              if (!strcasecmp(p_version, element->os_version)) {
                                  found = 1;
                                  break;
                              }
                          } else {
                              found = 1;
                              break;
                          }
                      }
                  } else {
                      found = 1;
                      break;
                  }
              }
          }
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "(DBG) Checking OS sysname ACL found=%d", found);
          if (!found)
              continue;
          log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "[plaintext] OS match (%s)", element->os_sysname);
      }

      /*  Application filtering? */
      debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
              "(DBG) current ACL apps=%p", p_acl->apps);

      if (element->app_name && p_acl->apps) {
          GSList *p_app = p_acl->apps;
          int found = 0;

          log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "[plaintext] Checking for App=[%s]", element->app_name);

          for ( ; p_app ; p_app = g_slist_next(p_app)) {
              if (!strcasecmp(((struct T_app*)p_app->data)->appname,
                          element->app_name)) {
                  found = 1;
                  break;
              }
          }
          log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "(DBG) Checking App ACL found=%d", found);
          if (!found)
              continue;
          log_message(VERBOSE_DEBUG, AREA_MAIN,
                  "[plaintext] App match (%s)", element->app_name);
      }
      /* period checking
       * */
      if (p_acl->period) {
          periodend=get_end_of_period_for_time_t(p_acl->period,time(NULL));
          if (periodend==0){
              /* this is not a match */
              continue;
          }
      }
      /*  We have a match 8-) */
      log_message(VERBOSE_DEBUG, AREA_MAIN,
              "[plaintext] matching with decision %d", p_acl->decision);
      this_acl=g_new0(struct acl_group, 1);
      g_assert(this_acl);
      this_acl->answer = p_acl->decision;
      this_acl->groups = g_slist_copy(p_acl->groups);
      this_acl->expire = periodend;
      g_list = g_slist_prepend(g_list, this_acl);
  }

  debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
          "[plaintext] We are leaving acl_check()");
  debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
          "(DBG) [plaintext] check_acls leaves with %p", g_list);
  return g_list;
}

