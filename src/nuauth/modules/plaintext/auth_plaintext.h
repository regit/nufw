/* $Id$ */

/*
** Copyright(C) 2004 Mikael Berthe <mikael+nufw@lists.lilotux.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 3 of the License.
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


#define TEXplaintext_USERFILE   CONFIG_DIR "/users.nufw"
#define TEXplaintext_ACLFILE    CONFIG_DIR "/acls.nufw"

struct plaintext_user {
	char *username;
	char *passwd;
	u_int32_t uid;
	GSList *groups;
};

struct plaintext_app {
	gchar *appname;
};

struct plaintext_os {
	char *sysname;
	char *release;
	char *version;
};

struct plaintext_ip {
	struct in6_addr addr;
	struct in6_addr netmask;
};

struct plaintext_ports {
	uint16_t firstport;
	int nbports;
};

struct plaintext_acl {
	char *aclname;
	decision_t decision;
	int proto;

	GSList *users;
	GSList *groups;
	GSList *apps;
	GSList *os;

	GSList *types;

	GSList *src_ip;
	GSList *src_ports;

	GSList *dst_ip;
	GSList *dst_ports;

	gchar *period;
	gchar *log_prefix;

	gint flags;
};

struct plaintext_params {
	char *plaintext_userfile;
	char *plaintext_aclfile;
	GSList *plaintext_userlist;
	GSList *plaintext_acllist;
};
