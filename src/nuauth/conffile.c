/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



/* taken a conf file and a hash 
 * fill the hash with corresponding values
 */


int parse_conffile(char * filename,gint array_size,confparams symbols[6]) {
  GScanner*  scanner;
  GTokenType dnentry=G_TOKEN_NONE;
  gpointer value;
  int fd,i;

  scanner=g_scanner_new(NULL);
  fd=open(filename,O_RDONLY);
  if (fd == -1)
    g_error("Can not open config file : %s",filename);
  g_scanner_input_file(scanner,fd);
  for (i = 0; i < array_size; i++)
    g_scanner_scope_add_symbol (scanner, 0, symbols[i].name, GINT_TO_POINTER (symbols[i].token));
  for (i = 0; i < array_size; i++){
    value = g_scanner_scope_lookup_symbol(scanner,0,symbols[i].name);
    if (value == NULL){
      g_warning("Did not find %s in confif file\n",symbols[i].name);
    } else {
      dnentry=g_scanner_get_next_token (scanner); 
      if (dnentry == G_TOKEN_SYMBOL){
	dnentry=g_scanner_get_next_token (scanner); 
	if (dnentry ==  G_TOKEN_EQUAL_SIGN){ 
	  dnentry=g_scanner_get_next_token (scanner); 
	  switch (dnentry){
	  case G_TOKEN_STRING :
	    /* test if element want a string */
	    if (symbols[i].token == G_TOKEN_STRING){
	      symbols[i].v_char=strdup(scanner->value.v_string);
	    } else {
	      g_warning("Bad argument value for %s at %u",
			symbols[i].name,scanner->line);
	      return -1;
	    }
	    break;
	  case G_TOKEN_INT :
	    /* test if element want a string */
	    if (symbols[i].token == G_TOKEN_INT){
	      symbols[i].v_int=scanner->value.v_int;
	    } else {
	      g_warning("Bad argument value for %s at %u",
			symbols[i].name,scanner->line);
	      return -1;
	    }
	    break;
	  default :
	    g_warning("Bad argument !\n");
	  }
	}
      }
    }
  }
  return 0;
}

gpointer get_confvar_value(confparams symbols[],gint array_size,gchar * confparam){
  gpointer value=NULL;
  int i;
  int token_type;
  /* go through symbol table */
  for (i = 0; i < array_size; i++){
    if (! strcmp(symbols[i].name,confparam) ){
      token_type = symbols[i].token;
      switch ( token_type ){
      case G_TOKEN_STRING :
	value=symbols[i].v_char;
	break;
      case G_TOKEN_INT :
	value=&(symbols[i].v_int);
	break;
      default :
	value=NULL;
	break;
      } 
      return value;
    }
  }
  return NULL;
}
