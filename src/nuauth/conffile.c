/*
 ** Copyright(C) 2003-2005 Eric Leblond <regit@inl.fr>
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




/**
 * taken a conf file and hash containing options, fill the hash with options values.
 * 
 * Argument 1 : filename
 * Argument 2 : size of the array
 * Argument 3 : pointer to a hash containing options
 * Return : 1 if OK, 0 otherwise
 */

int parse_conffile(char * filename,gint array_size,confparams* symbols) 
{
	GScanner*  scanner;
	GTokenType dnentry=G_TOKEN_NONE;
	int fd,i;
	gboolean done;
	confparams* current_symbol=NULL;

	scanner=g_scanner_new(NULL);
	fd=open(filename,O_RDONLY);
	if (fd == -1)
    {
		g_error("Can not open config file : %s",filename);
        exit (EXIT_FAILURE);
    }
	g_scanner_input_file(scanner,fd);
	for (i = 0; i < array_size; i++)
		g_scanner_scope_add_symbol (scanner, 0, symbols[i].name, GINT_TO_POINTER (i));

	done = FALSE;
	while (!done){
		dnentry=g_scanner_get_next_token (scanner);
		if (dnentry == G_TOKEN_EOF){
			done=TRUE;
			break;
		}
		if (dnentry == G_TOKEN_SYMBOL){
			current_symbol=NULL;
			for (i = 0; i < array_size; i++){
				if (i == GPOINTER_TO_INT(scanner->value.v_symbol)){
					current_symbol=symbols+i;
					break;
				}
			}
			if (current_symbol != NULL){
				dnentry=g_scanner_get_next_token (scanner); 
				if (dnentry ==  G_TOKEN_EQUAL_SIGN){ 
					dnentry=g_scanner_get_next_token (scanner); 
					switch (dnentry){
						case G_TOKEN_STRING :
							/* test if element want a string */
							if (current_symbol->value_type == G_TOKEN_STRING){
								current_symbol->v_char=g_strdup(scanner->value.v_string);
							} else {
								g_warning("Bad argument value for %s at %u",
										current_symbol->name,scanner->line);
								g_scanner_destroy (scanner);
								return 0;
							}
							break;
						case G_TOKEN_INT :
							/* test if element want a string */
							if (current_symbol->value_type == G_TOKEN_INT){
								current_symbol->v_int=scanner->value.v_int;
							} else {
								g_warning("Bad argument value for %s at %u",
										current_symbol->name,scanner->line);
								g_scanner_destroy (scanner);
								return 0;
							}
							break;
						default :
							g_warning("Bad argument !\n");
					}
				}
			} else {
				g_warning("Did not find a symbol at %d,%d",scanner->line,scanner->position);
			}
		}
	}
	g_scanner_destroy (scanner);
	close(fd);
	return 1;
}


/**
 * fetch value of an option and return a pointer to it.
 * 
 * Argument 1 : option hash
 * Argument 2 : size of hash
 * Argument 3 : name of param to get
 * Return : pointer to param
 */

gpointer get_confvar_value(confparams* symbols,gint array_size,gchar * confparam){
	gpointer value=NULL;
	int i;
	int token_type;
	/* go through symbol table */
	for (i = 0; i < array_size; i++){
		if (! strcmp(symbols[i].name,confparam) ){
			token_type = symbols[i].value_type;
			switch ( token_type ){
				case G_TOKEN_STRING :
#if 0
					value=symbols[i].v_char;
#endif
					value=g_strdup(symbols[i].v_char);
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
