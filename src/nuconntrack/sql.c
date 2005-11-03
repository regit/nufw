/*
 ** Copyright(C) 2005 INL
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

/* 
 * Initialize connection to mysql server
 */

MYSQL* mysql_conn_init(void){
	MYSQL *ld = NULL;

	/* init connection */
	ld = mysql_init(ld);     
	if (ld == NULL) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
			g_warning("mysql init error : %s\n",strerror(errno));
		return NULL;
	}
	if (!mysql_real_connect(ld,mysql_server,mysql_user,mysql_passwd,mysql_db_name,mysql_server_port,NULL,0)) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
			g_warning("mysql connection failed : %s\n",mysql_error(ld));
		return NULL;
	}
	return ld;
}


void mysql_work(void)
{
	
}


