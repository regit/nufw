/* $Id: auth_dbm.h,v 1.3 2003/09/30 22:33:28 gryzor Exp $ */

/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 2 of the License.
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

#include <sys/time.h>
#include <gdbm.h>


#define DBM_USERS_FILE "/etc/nuauth/nuauth_users.dbm"
//DBM_BLOCK_SIZE is useless (ignored on file reads, and file is ALWAYS read
#define DBM_BLOCK_SIZE 512
#define DBM_FILE_ACCESS_MODE GDBM_READER
//DBM_FILE_MODE is ignored on read too
#define DBM_FILE_MODE 777
#define DBM_FATAL_FUNCTION 0


struct dbm_data_struct{ 
	char *passwd;
	GSList *outelt;
};
	
struct dbm_data_struct analyse_dbm_char(char *data);

char * users_file;
