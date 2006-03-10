/* $Id: dict.c,v 1.2 2003/01/23 00:36:01 robertc Exp $ 
* Copyright (C) 2002 Rodrigo Campos
*           (C) 2004-2005 Vincent Deffontaines - INL
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; version 2 of the License.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
* Author: Rodrigo Campos (rodrigo@geekbunker.org)
* Adaptation to NuFW by Vincent Deffontaines
* 
*/
			  

#include "nutrackd.h"

const char *const w_space = " \t\n\r";


static void parse_char(char **ourchar)
{
  char *token = strtok(NULL,w_space);
  if (token == NULL) {
      *ourchar = NULL;
  } else {
      *ourchar = strdup(token);
  }
}

static void parse_unsigned_int(unsigned int *value)
{
  char *token = strtok(NULL,w_space);
  if (token == NULL)
      *value = 0;
  else
  {
      *value = atoi(token);
  }
}



SQLconnection * read_conf (FILE * FH)
{
  SQLconnection *our_conn;
  char line[256];		/* the buffer for the lines read
				   from the config file */
  char *cp;
  char *token;			/* a char pointer used to parse
				   each line */

  our_conn = malloc (sizeof (SQLconnection));
#ifdef DB_TYPE_MYSQL
  our_conn->port = 3306;
#else
  our_conn->port = 5432;
#endif
  our_conn->timeout = 15;

  while ((cp = fgets (line, sizeof (line), FH)) != NULL) {
		  if (line[0] == '#') {
				  continue;
		  }
    if ((cp = strchr (line, '\n')) != NULL) {
      /* chop \n characters */
      *cp = '\0';
    }
    if (line == NULL)
        continue;
    if ((token = strtok(line, w_space)) == NULL)
        continue; /* Ignore empty lines; */
    else if(!strcmp(token,"db_host"))
        parse_char(&our_conn->host);
    else if(!strcmp(token,"db_port"))
        parse_unsigned_int(&our_conn->port);
    else if(!strcmp(token,"db_database"))
        parse_char(&our_conn->database);
    else if(!strcmp(token,"db_table"))
        parse_char(&our_conn->table);
    else if(!strcmp(token,"db_user"))
        parse_char(&our_conn->user);
    else if(!strcmp(token,"db_pass"))
        parse_char(&our_conn->pass);
    else if(!strcmp(token,"db_timeout"))
        parse_unsigned_int(&our_conn->timeout);
  }
  return our_conn;
}
