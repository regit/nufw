
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

#include <string.h>

#include <auth_srv.h>
#include "auth_plaintext.h"


confparams plaintext_nuauth_vars[] = {
  { "plaintext_userfile", G_TOKEN_STRING, 0, TEXT_USERFILE },
  { "plaintext_aclfile",  G_TOKEN_STRING, 0, TEXT_ACLFILE }
};


/**
 * strip_line()
 * Returns a pointer on stripped line or
 * NULL if the line should be skipped and acceptnull is true.
 */
char *strip_line(char *line, int acceptnull)
{
  char *p_tmp;

  // Let's get rid of tabs and spaces
  while ((*line == 32) || (*line == 9))
      line++;
  // Let's get rid of trailing characters
  for (p_tmp = line; *p_tmp; p_tmp++)
      ;
  if (p_tmp != line)
      p_tmp--;
  for ( ; p_tmp>line && (*p_tmp=='\x0a' || *p_tmp=='\x0d' ||
              *p_tmp==32 || *p_tmp==9); *p_tmp-- = 0)
      ;

  if (!acceptnull)
      return line;

  // Discard comments and empty lines
  if (*line == '#' || *line == 0 ||
          *line == '\x0d' || *line == '\x0a')
      return NULL;

  return line;
}

/**
 * parse_groups()
 * Extracts group ids in groupline and fills *p_grouplist.
 * prefix is displayed in front of the log messages.
 * Returns 0 if successful.
 */
int parse_groups(char *groupline, GSList **p_grouplist, char *prefix)
{
  char *p_nextgroup;
  char *p_groups = groupline;
  GSList *grouplist = *p_grouplist;
  int group;

  // parsing groups
  while (p_groups) {
      p_nextgroup = strchr(p_groups, ',');
      if (p_nextgroup) {
          *p_nextgroup = 0;
      }
      if (sscanf(p_groups, "%u", &group) != 1) {
          // We can't read a group.  This will be an error only if we can
          //  see a comma next.
          if (p_nextgroup) {
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                  g_message("%s parse_groups: Malformed line",
                          prefix);
              *p_grouplist = grouplist;
              return 1;
          }
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
              g_message("%s parse_groups: Garbarge at end of line", prefix);
      } else {
          // One group to add...
          grouplist = g_slist_prepend(grouplist, 
                      GINT_TO_POINTER((u_int32_t)group));
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("%s Added group %d", prefix, group);
#endif
      }
      if ((p_groups = p_nextgroup))
          p_groups++;
  }

  *p_grouplist = grouplist;
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

  // parsing ports
  while (p_ports) {
      p_nextports = strchr(p_ports, ',');
      if (p_nextports) {
          *p_nextports = 0;
      }
      n = sscanf(p_ports, "%d-%d", &fport, &lastport);
      ports.firstport = (uint16_t) fport;
      if ((n != 1) && (n != 2)) {
          // We can't read a port number.  This will be an error only if we can
          //  see a comma next.
          if (p_nextports) {
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                  g_message("%s parse_ports: Malformed line", prefix);
              *p_portslist = portslist;
              return 1;
          }
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
              g_message("%s parse_ports: Garbarge at end of line", prefix);
      } else {
          struct T_ports *this_port;
          // One port or ports range to add...
          if (n == 2) {  // That's a range
              if (lastport >= fport)
                  ports.nbports = lastport - fport;
              else {
                  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                      g_message("%s parse_ports: Malformed line", prefix);
	      }
          } else
              ports.nbports = 0;

          this_port = g_new0(struct T_ports, 1);
          this_port->firstport = ports.firstport;
          this_port->nbports = ports.nbports;
          portslist = g_slist_prepend(portslist, this_port);
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("%s Adding Port = %d, number = %d", prefix,
                      ports.firstport, ports.nbports);
#endif
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

  // parsing IPs
  // XXX only IPv4 for now
  while (p_ip) {
      int n = 1;
      uint32_t mask = 0;
      int imask = 0;

      p_nextip = strchr(p_ip, ',');
      if (p_nextip) {
          *p_nextip = 0;
      }

      p_ip = strip_line(p_ip, FALSE);
      // Is there a netmask?
      p_tmp = strchr(p_ip, '/');
      if (p_tmp) {
          *p_tmp++ = 0;
          n = sscanf(p_tmp, "%d", &imask);
          mask = (uint32_t) imask;
      } else    // no -> default netmask is 32 bits
          mask = 32;

      if ((n != 1) || (inet_pton(AF_INET, p_ip, &ip_addr) <= 0)) {
          // We can't read an IP address.  This will be an error only if we can
          //  see a comma next.
          if (p_nextip) {
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                  g_message("%s parse_ips: Malformed line", prefix);
              *p_ipslist = ipslist;
              return 1;
          }
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
              g_message("%s parse_ips: Garbarge at end of line", prefix);
      } else {
          struct T_ip *this_ip = g_new0(struct T_ip, 1);

          memcpy(&this_ip->addr, &ip_addr, sizeof(ip_addr));

          // Netmask conversion
          p_netmask = (uint32_t *)&this_ip->netmask.s_addr;
          for (n = 0 ; n < (int)mask ; n++) {
              *p_netmask <<= 1;
              *p_netmask |= 1;
          }

          p_address = (uint32_t *)&this_ip->addr.s_addr;

          if ((*p_address & *p_netmask) != *p_address) {
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                  g_message("%s parse_ips: Invalid network specification!",
                          prefix);
              *p_address &= *p_netmask;
          }

          ipslist = g_slist_prepend(ipslist, this_ip);

#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("%s Adding IP = %u, netmask = %u", prefix,
                      this_ip->addr.s_addr, this_ip->netmask.s_addr);
#endif
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
int read_user_list(void)
{
  struct T_plaintext_user *plaintext_user;
  FILE *fd;
  char line[1024];
  char *p_username, *p_passwd, *p_uid, *p_groups;
  int iuid;
  u_int16_t uid;
  char log_prefix[16];
  int ln = 0;   // Line number

  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
      g_message("[plaintext] read_user_list: reading [%s]", plaintext_userfile);

  fd = fopen(plaintext_userfile, "r");

  if (!fd) {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
        g_message("read_user_list: fopen error");
      return 1;
  }

  while (fgets(line, 1000, fd)) {
      ln++;
      p_username = strip_line(line, TRUE);

      if (!p_username)
          continue;
      // TODO: check for bad characters

      // User Name
      if (!p_username) {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_message("L.%d: read_user_list: Malformed line (no username)", ln);
          fclose(fd);
          return 2;
      }

      // Password
      p_passwd = strchr(p_username, ':');
      if (!p_passwd) {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_message("L.%d: read_user_list: Malformed line (no passwd)", ln);
          fclose(fd);
          return 2;
      }
      *p_passwd++ = 0;

      // UID
      p_uid = strchr(p_passwd, ':');
      if (!p_uid) {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_message("L.%d: read_user_list: Malformed line (no uid)", ln);
          fclose(fd);
          return 2;
      }
      *p_uid++ = 0;
      if (sscanf(p_uid, "%d", &iuid) != 1) {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
              g_message("L.%d: read_user_list: Malformed line "
                      "(uid should be a number)", ln);
          fclose(fd);
          return 2;
      }
      uid = (u_int16_t) iuid;

      // List of groups
      p_groups = strchr(p_uid, ':');
      if (!p_groups) {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_message("L.%d: read_user_list: Malformed line (no groups)", ln);
          fclose(fd);
          return 2;
      }
      *p_groups++ = 0;

#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
          g_message("L.%d: Read username=[%s], uid=%d", ln, p_username, uid);
#endif

      // Let's create an user node
      plaintext_user = g_new0(struct T_plaintext_user, 1);
      if (!plaintext_user) {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_message("read_user_list: Cannot allocate T_plaintext_user!");
          fclose(fd);
          return 5;
      }
      plaintext_user->groups = NULL;
      plaintext_user->passwd = g_strdup(p_passwd);
      plaintext_user->username = g_strdup(p_username);
      plaintext_user->uid = uid;

      snprintf(log_prefix, 15, "L.%d: ", ln);
      // parsing groups
      if (parse_groups(p_groups, &plaintext_user->groups, log_prefix)) {
          g_free(plaintext_user);
          fclose(fd);
          return 2;
      }

      // User node is ready
      plaintext_userlist = g_slist_prepend(plaintext_userlist, plaintext_user);
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
int read_acl_list(void)
{
  FILE *fd;
  char line[1024];
  char *p_key, *p_value, *p_tmp;
  struct T_plaintext_acl *newacl = NULL;
  int ln = 0;   // Line number

  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
      g_message("[plaintext] read_acl_list: reading [%s]", plaintext_aclfile);

  fd = fopen(plaintext_aclfile, "r");

  if (!fd) {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
        g_message("read_acl_list: fopen error");
      return 1;
  }

  while (fgets(line, 1000, fd)) {
      ln++;
      p_key = strip_line(line, TRUE);

      if (!p_key)
          continue;

      // New ACL?
      if (p_key[0] == '[') {
          if (newacl) {
#ifdef DEBUG_ENABLE
              if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
                  g_message("Done with ACL [%s]", newacl->aclname);
#endif
              // check if ACL node has minimal information (protocol?)
              // Warning: this code is duplicated after the loop
              if (newacl->proto == IPPROTO_TCP || newacl->proto == IPPROTO_UDP
                      || newacl->proto == IPPROTO_ICMP) {
                  // ACL node is ready
                  plaintext_acllist = g_slist_prepend(plaintext_acllist, newacl);
              } else {
                  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
                      g_message("No valid protocol declared in ACL %s",
                              newacl->aclname);
              }
          }

#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("L.%d: New ACL", ln);
#endif

          p_tmp = strchr(++p_key, ']');
          if (!p_tmp) {
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                  g_message("L.%d: Malformed line (ACLname)", ln);
              fclose(fd);
              return 2;
          }
          *p_tmp = 0;
          // Ok, new ACL declaration here.  Let's allocate a structure!
          newacl = g_new0(struct T_plaintext_acl, 1);
          if (!newacl) {
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                  g_message("read_acl_list: Cannot allocate T_plaintext_acl!");
              fclose(fd);
              return 5;
          }

          newacl->aclname = g_strdup(p_key);
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("L.%d: ACL name found: [%s]", ln, newacl->aclname);
#endif
          // We're done with this line
          continue;
      }

      // We shouldn't be here if we aren't in an ACL declaration
      if (!newacl) {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
              g_message("L.%d: Malformed line (Not in an ACL declaration)",
                      ln);
          fclose(fd);
          return 2;
      }

      p_value = strchr(p_key, '=');
      if (!p_value) {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
              g_message("L.%d: Malformed line (No '=' inside)", ln);
          fclose(fd);
          return 2;
      }
      *p_value++ = 0;

      p_key   = strip_line(p_key, FALSE);
      p_value = strip_line(p_value, FALSE);

      // Ok.  Let's study the key/value we've found, now.
      if (!strcasecmp("decision", p_key)) {                     // Decision
          if (!strcmp(p_value, "1"))
              newacl->decision = OK;
          else if (strcmp(p_value, "0")) {
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                  g_message("L.%d: Malformed line (decision should be 0 or 1)",
                          ln);
              fclose(fd);
              return 2;
          }
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("L.%d: Read decision = %d", ln, newacl->decision);
#endif
      } else if (!strcasecmp("gid", p_key)) {                   // Groups
          char log_prefix[16];
          snprintf(log_prefix, 15, "L.%d: ", ln);
          // parsing groups
          if (parse_groups(p_value, &newacl->groups, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("proto", p_key)) {                 // Protocol
          if (sscanf(p_value, "%d", &newacl->proto) != 1) {
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                  g_message("L.%d: Malformed line (proto should be a number)",
                          ln);
              fclose(fd);
              return 2;
          }
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("L.%d: Read proto = %d", ln, newacl->proto);
#endif
      } else if (!strcasecmp("srcip", p_key)) {                 // SrcIP
          char log_prefix[16];
          snprintf(log_prefix, 15, "L.%d: ", ln);
          // parsing IPs
          if (parse_ips(p_value, &newacl->src_ip, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("srcport", p_key)) {               // SrcPort
          char log_prefix[16];
          snprintf(log_prefix, 15, "L.%d: ", ln);
          // parsing ports
          if (parse_ports(p_value, &newacl->src_ports, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("dstip", p_key)) {                 // DstIP
          char log_prefix[16];
          snprintf(log_prefix, 15, "L.%d: ", ln);
          // parsing IPs
          if (parse_ips(p_value, &newacl->dst_ip, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("dstport", p_key)) {               // DstPort
          char log_prefix[16];
          snprintf(log_prefix, 15, "L.%d: ", ln);
          // parsing ports
          if (parse_ports(p_value, &newacl->dst_ports, log_prefix)) {
              fclose(fd);
              return 2;
          }
      } else if (!strcasecmp("app", p_key)) {                   // App
          char *sep;
          struct T_app *newapp = g_new0(struct T_app, 1);

          sep = strchr(p_value, ';');
          if (sep)
              *sep++ = 0;
          newapp->appname = g_strdup(strip_line(p_value, 0));
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("L.%d: Read App name [%s]", ln, newapp->appname);
#endif

          // MD5:
          if (sep) {
              p_value = sep;
              newapp->appmd5 = g_strdup(strip_line(p_value, 0));
#ifdef DEBUG_ENABLE
              if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
                  g_message("L.%d: Read App MD5 [%s]", ln, newapp->appmd5);
#endif
          }
          // TODO checks
          newacl->apps = g_slist_prepend(newacl->apps, newapp);
      } else if (!strcasecmp("os", p_key)) {                    // OS
          char *sep;
          struct T_os *newos = g_new0(struct T_os, 1);

          sep = strchr(p_value, ';');
          if (sep)
              *sep++ = 0;
          newos->sysname = g_strdup(strip_line(p_value, 0));
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("L.%d: Read OS sysname [%s]", ln, newos->sysname);
#endif

          // Release:
          if (sep) {
              p_value = sep;
              sep = strchr(p_value, ';');
              if (sep)
                  *sep++ = 0;
              newos->release = g_strdup(strip_line(p_value, 0));
#ifdef DEBUG_ENABLE
              if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
                  g_message("L.%d: Read OS release [%s]", ln, newos->release);
#endif
          }
          // Version:
          if (sep) {
              p_value = sep;
              newos->version = g_strdup(strip_line(p_value, 0));
#ifdef DEBUG_ENABLE
              if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
                  g_message("L.%d: Read OS version [%s]", ln, newos->version);
#endif
          }

          // TODO checks
          newacl->os = g_slist_prepend(newacl->os, newos);
      } else {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
              g_message("L.%d: Unknown key [%s] in ACL %s", ln,
                      p_key, newacl->aclname);
      } // End of key/value parsing
  }
  if (newacl) {

#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
          g_message("Done with ACL [%s]", newacl->aclname);
#endif
      // check if ACL node has minimal information (protocol?)
      // Warning: this code is duplicated after the loop
      if (newacl->proto == IPPROTO_TCP || newacl->proto == IPPROTO_UDP ||
              newacl->proto == IPPROTO_ICMP) {
          // ACL node is ready
          plaintext_acllist = g_slist_prepend(plaintext_acllist, newacl);
      } else if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
          g_message("No valid protocol declared in ACL %s", newacl->aclname);
  }

  return 0;
}

G_MODULE_EXPORT gchar* g_module_unload(void)
{
  // Free user list
  if (plaintext_userlist) {
      GSList *p_userlist;
      struct T_plaintext_user *p_user;

#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
          g_message("Freeing users list");
#endif

      // Let's free each node separately
      for (p_userlist = plaintext_userlist ; p_userlist ;
              p_userlist = g_slist_next(p_userlist)) {
          p_user = (struct T_plaintext_user*) p_userlist->data;
          g_free(p_user->passwd);
          g_free(p_user->username);
          if (p_user->groups)
              g_slist_free(p_user->groups);
      }
      // Now we can free the list
      g_slist_free(plaintext_userlist);
      plaintext_userlist = NULL;
  }

  // Free acl list
  if (plaintext_acllist) {
      GSList *p_acllist;
      struct T_plaintext_acl *p_acl;

#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
          g_message("Freeing ACLs");
#endif

      // Let's free each node separately
      for (p_acllist = plaintext_acllist ; p_acllist ;
              p_acllist = g_slist_next(p_acllist)) {
          p_acl = (struct T_plaintext_acl*) p_acllist->data;
          g_free(p_acl->aclname);
          if (p_acl->groups)
              g_slist_free(p_acl->groups);
          // Let's free each appname(/appmd5)
          if (p_acl->apps) {
              GSList *p_app = p_acl->apps;
              for ( ; p_app ; p_app = g_slist_next(p_app)) {
                  g_free(((struct T_app*)p_app->data)->appname);
                  if (((struct T_app*)p_app->data)->appmd5)
                      g_free(((struct T_app*)p_app->data)->appmd5);
              }
              g_slist_free(p_acl->apps);
              g_free(p_acl);
          }
          // FIXME: free IPs
          // FIXME: free ports
      }
      // Now we can free the list
      g_slist_free(plaintext_acllist);
      plaintext_acllist = NULL;
  }

  return NULL;
}


/* Init plaintext system */
G_MODULE_EXPORT gchar* g_module_check_init(GModule *module)
{
  gpointer vpointer;

  // init global variables
  plaintext_userfile = TEXT_USERFILE;
  plaintext_aclfile  = TEXT_ACLFILE;

  // parse conf file
  parse_conffile(DEFAULT_CONF_FILE,
          sizeof(plaintext_nuauth_vars)/sizeof(confparams),
          plaintext_nuauth_vars);
  // set variables
  vpointer = get_confvar_value(plaintext_nuauth_vars,
          sizeof(plaintext_nuauth_vars)/sizeof(confparams),
          "plaintext_userfile");
  plaintext_userfile = (char *)(vpointer?vpointer:plaintext_userfile);
  vpointer = get_confvar_value(plaintext_nuauth_vars,
          sizeof(plaintext_nuauth_vars)/sizeof(confparams),
          "plaintext_aclfile");
  plaintext_aclfile  = (char *)(vpointer?vpointer:plaintext_aclfile);

  return NULL;
}

// This function is used by g_slist_find_custom() in user_check().
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
        unsigned passlen, uint16_t* uid, GSList **groups)
{
  GSList *outelt = *groups;
  GSList *res;
  struct T_plaintext_user ref;
  char *realpass;
  int initstatus;
  char *user;

  // Initialization if the user list is empty
  if (!plaintext_userlist) {
      initstatus = read_user_list();
      if (initstatus &&
              DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH)) {
          g_message("Can't parse users file [%s]", plaintext_userfile);
          return SASL_BADAUTH;
      }
  }

  /* strip username from domain */
  user = get_rid_of_domain((char*)username);
#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
  		g_message("Looking for group(s) for user %s", user);
#endif
  // Let's look for the first node with matching username
  ref.username = (char*)user;
  res = g_slist_find_custom(plaintext_userlist, &ref,
          (GCompareFunc)find_by_username);

  if (!res) {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
          g_message("Unknown user [%s]!", user);
      return SASL_BADAUTH;
  }

  realpass = ((struct T_plaintext_user*)res->data)->passwd;

  if (!strcmp(realpass, "*") || !strcmp(realpass, "!")) {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
          g_message("user_check: Account is disabled (%s)", user);
      return SASL_BADAUTH;
  }

  // If both clientpass and passlen are null, we just need to
  // return the groups list (no checks needed)
  if (clientpass) {
      if (verify_user_password(clientpass, realpass) != SASL_OK ){
          if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
              g_message("user_check: Wrong password for %s", user);
          return SASL_BADAUTH;
      }
  }

  outelt = g_slist_copy(((struct T_plaintext_user*)res->data)->groups);

#ifdef DEBUG_ENABLE
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
      g_message("We are leaving (plaintext) user_check()");
#endif

  *groups = outelt;
  *uid = ((struct T_plaintext_user*)res->data)->uid;

  return SASL_OK;
}

// acl_check()
G_MODULE_EXPORT GSList* acl_check(connection* element)
{
  GSList *g_list = NULL;
  GSList *p_acllist;
  struct acl_group *this_acl;
  tracking *netdata = &element->tracking_hdrs;
  struct T_plaintext_acl *p_acl;
  int initstatus;
  uint32_t src_ip, dst_ip;

  // Initialization if the ACL list is empty
  if (!plaintext_acllist) {
      initstatus = read_acl_list();
      if (initstatus &&
              DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH)) {
          g_message("Can't parse ACLs file [%s]", plaintext_aclfile);
          return NULL;
      }
  }

  // netdata.protocol   // IPPROTO_TCP || IPPROTO_UDP || IPPROTO_ICMP
  // netdata.type       // for ICMP
  // netdata.code       // for ICMP
  // netdata.saddr      // IP source
  // netdata.daddr      // IP destination
  // netdata.source     // Port source
  // netdata.dest       // Port destination

  src_ip = ntohl(netdata->saddr);
  dst_ip = ntohl(netdata->daddr);

#ifdef DEBUG_ENABLE
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)) {
      g_message("(DBG) acl_check -- appname: %p", element->appname);
      g_message("(DBG) acl_check -- appmd5 : %p", element->appmd5);
      g_message("(DBG) acl_check -- sysname: %p", element->sysname);
  }
#endif
  for (p_acllist = plaintext_acllist ; p_acllist ;
          p_acllist = g_slist_next(p_acllist)) {
      p_acl = (struct T_plaintext_acl*)p_acllist->data;

      if (netdata->protocol != p_acl->proto)
              continue;

      // O.S. filtering?
#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
          g_message("(DBG) current ACL os=%p", p_acl->os);
#endif
      if (element->sysname && p_acl->os) {
          GSList *p_os = p_acl->os;
          gchar *p_sysname, *p_release, *p_version;
          int found = 0;

          // sysname
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("[plaintext] Checking for OS sysname=[%s]",
                      element->sysname);

          for ( ; p_os ; p_os = g_slist_next(p_os)) {
              p_sysname = ((struct T_os*)p_os->data)->sysname;
              p_release = ((struct T_os*)p_os->data)->release;
              p_version = ((struct T_os*)p_os->data)->version;
              if (!strcasecmp(p_sysname, element->sysname)) {
                  if (element->release && p_release) {
                      if (!strcasecmp(p_release, element->release)) {
                          if (element->version && p_version) {
                              if (!strcasecmp(p_version, element->version)) {
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
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("(DBG) Checking OS sysname ACL found=%d", found);
#endif
          if (!found)
              continue;
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("[plaintext] OS match (%s)",
                      element->sysname);
      }

      // Application filtering?
#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
          g_message("(DBG) current ACL apps=%p", p_acl->apps);
#endif
      if (element->appname && p_acl->apps) {
          GSList *p_app = p_acl->apps;
          int found = 0;

          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("[plaintext] Checking for App=[%s]",
                      element->appname);

          for ( ; p_app ; p_app = g_slist_next(p_app)) {
              if (!strcasecmp(((struct T_app*)p_app->data)->appname,
                          element->appname)) {
                  found = 1;
                  break;
              }
          }
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("(DBG) Checking App ACL found=%d", found);
#endif
          if (!found)
              continue;
          if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
              g_message("[plaintext] App match (%s)",
                      element->appname);
      }

      // Check source address
      if (!p_acl->src_ip)
          continue;
      else {
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
              continue; // We don't have a match
      }
      // Check destination address
      if (!p_acl->dst_ip)
          continue;
      else {
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
              continue; // We don't have a match
      }

      // ICMP?
      if (netdata->protocol == IPPROTO_ICMP) {
	      // TODO Check ICMP
	      g_message("[plaintext] ICMP code not yet supported! :-(\n");
	      g_message("[plaintext] faking ICMP support");
	      if (p_acl->proto == IPPROTO_ICMP){
	      	g_message("[plaintext] ICMP acls");
	      }
      } else {
	      // Following is only for TCP / UDP  (ports stuff...)
	      if (p_acl->proto != IPPROTO_TCP && p_acl->proto != IPPROTO_UDP) {
		      g_message("[plaintext] Unsupported protocol: %d", p_acl->proto);
		      continue;
	      }

	      // Check source port
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
	      // Check destination port
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
		      if (!found)
			      continue;
	      }
      }
      // We have a match 8-)
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
      g_message("[plaintext] matching with decision %d", p_acl->decision);
  }
      this_acl=g_new0(struct acl_group, 1);
      g_assert(this_acl);
      this_acl->answer = p_acl->decision;
      this_acl->groups = g_slist_copy(p_acl->groups);
      g_list = g_slist_prepend(g_list, this_acl);
  }

#ifdef DEBUG_ENABLE
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
    g_message("[plaintext] We are leaving acl_check()");
  	g_message("(DBG) [plaintext] check_acls leaves with %p", g_list);
  }
#endif
  return g_list;
}

