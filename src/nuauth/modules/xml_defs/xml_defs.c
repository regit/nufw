/*
** Copyright(C) 2006 INL
**          written by Eric Leblond <regit@inl.fr>
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


#include <auth_srv.h>
#include "xml_defs.h"

#define XML_DEFS_PERIODFILE CONFIG_DIR "/" "periods.xml"

G_MODULE_EXPORT gboolean module_params_unload(gpointer params_p)
{
  struct xml_defs_params* params=(struct xml_defs_params*)params_p;
  /*  Free user list */
  if (params){
      g_free(params->xml_defs_periodfile);
  }
  g_free(params);
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
  confparams xml_defs_nuauth_vars[] = {
      { "xml_defs_periodfile", G_TOKEN_STRING, 0, g_strdup(XML_DEFS_PERIODFILE) }
  };
  gpointer vpointer;
  struct xml_defs_params* params=g_new0(struct xml_defs_params,1);

  /*  init global variables */
  params->xml_defs_periodfile = XML_DEFS_PERIODFILE;

  /*  parse conf file */
  if (module->configfile){
      parse_conffile(module->configfile,
              sizeof(xml_defs_nuauth_vars)/sizeof(confparams),
              xml_defs_nuauth_vars);
  } else {
      parse_conffile(DEFAULT_CONF_FILE,
              sizeof(xml_defs_nuauth_vars)/sizeof(confparams),
              xml_defs_nuauth_vars);
  }
  /*  set variables */
  vpointer = get_confvar_value(xml_defs_nuauth_vars,
          sizeof(xml_defs_nuauth_vars)/sizeof(confparams),
          "xml_defs_periodfile");
  params->xml_defs_periodfile = (char *)(vpointer?vpointer:params->xml_defs_periodfile);

  /* free config struct */
  free_confparams(xml_defs_nuauth_vars,sizeof(xml_defs_nuauth_vars)/sizeof(confparams));

  module->params = (gpointer) params; 
  return TRUE;
}

struct xml_period_context {
    gchar* periodname;
    struct period_item* perioditem;
    GHashTable * periods;
};


static void period_start_element_handler (GMarkupParseContext *context,
		const gchar *element_name,
		const gchar **attribute_names,
		const gchar **attribute_values,
		gpointer user_data,
		GError **error) 
{

    struct xml_period_context* curcontext=(struct xml_period_context*)user_data;
    int i;

    if(! strcmp(element_name, "period")){
        const char * p_name=NULL;
        const char *p_desc=NULL;
        for(i = 0; attribute_names[i]; i++) {
            if (!strcmp(attribute_names[i], "name")) {
                p_name = attribute_values[i];
            } else if (!strcmp(attribute_names[i], "desc")) {
                p_desc = attribute_values[i];
            }

        } 
        if (p_name ){
            if (!p_desc){
                p_desc="";
            }
            define_new_period(curcontext->periods,g_strdup(p_name),g_strdup(p_desc));
            curcontext->periodname=g_strdup(p_name);
            log_message(DEBUG,AREA_MAIN,"Adding period %s (%s)",p_name,p_desc);
        }
    } else if (! strcmp(element_name, "perioditem")) {
        curcontext->perioditem=g_new0(struct period_item,1);
        curcontext->perioditem->start_date=-1;
        curcontext->perioditem->end_date=-1;
        curcontext->perioditem->start_day=-1;
        curcontext->perioditem->end_day=-1;
        curcontext->perioditem->start_hour=-1;
        curcontext->perioditem->end_hour=-1;
    } else if (! strcmp(element_name, "days")) {
        if (curcontext->perioditem) {
            for(i = 0; attribute_names[i]; i++) {
                if(!strcmp(attribute_names[i], "start")) {
                    curcontext->perioditem->start_day=atoi(attribute_values[i]);
                } else if (!strcmp(attribute_names[i], "end")) {
                    curcontext->perioditem->end_day=atoi(attribute_values[i]);
                } 
            }
        }
    } else if (! strcmp(element_name, "hours")) {
        if (curcontext->perioditem) {
            for(i = 0; attribute_names[i]; i++) {
                if(!strcmp(attribute_names[i], "start")) {
                    curcontext->perioditem->start_hour=atoi(attribute_values[i]);
                } else if (!strcmp(attribute_names[i], "end")) {
                    curcontext->perioditem->end_hour=atoi(attribute_values[i]);
                } 
            }
        }
    } else if (! strcmp(element_name, "dates")) {
        if (curcontext->perioditem) {
            for(i = 0; attribute_names[i]; i++) {
                if(!strcmp(attribute_names[i], "start")) {
                    curcontext->perioditem->start_date=atoi(attribute_values[i]);
                } else if (!strcmp(attribute_names[i], "end")) {
                    curcontext->perioditem->end_date=atoi(attribute_values[i]);
                } 
            }
        }
    }
}

static void period_end_element_handler (GMarkupParseContext *context,
		const gchar *element_name,
		gpointer user_data,
		GError **error) 
{
    struct xml_period_context* curcontext=(struct xml_period_context*)user_data;
            
    if(! strcmp(element_name, "perioditem")) {
        if (curcontext->periodname){
            add_perioditem_to_period(curcontext->periods,g_strdup(curcontext->periodname),curcontext->perioditem);
        } else {
            log_message(WARNING,AREA_MAIN,"not in period but end of perioditem");
        }
        curcontext->perioditem=NULL;
    } else if(! strcmp(element_name, "period")){
        g_free(curcontext->periodname);
        curcontext->periodname=NULL;
    }
}



static GMarkupParser period_parser = {
	period_start_element_handler,
	period_end_element_handler,
	NULL,
	NULL,
	NULL
};

G_MODULE_EXPORT void define_periods(GHashTable* periods,gpointer params_p)
{
	GMarkupParseContext *context;
    struct xml_defs_params* params=(struct xml_defs_params *) params_p;
	gchar *contents = NULL;
	gsize length;
	GError *error = NULL;
    struct xml_period_context * curcontext=g_new0(struct xml_period_context,1);


    curcontext->periods=periods;
    if (!g_file_get_contents(params->xml_defs_periodfile, &contents, &length, &error)) {
        log_message(SERIOUS_WARNING, AREA_MAIN,"Error reading period: %s\n",
                error->message);
        g_error_free(error);
        return;
    }

	context = g_markup_parse_context_new(&period_parser, 0, curcontext, NULL);

	if(!g_markup_parse_context_parse(context, contents, length, NULL)) {
		g_markup_parse_context_free(context);
		g_free(contents);
        g_free(curcontext);
		return;
	}
    g_free(curcontext);

    return;
}
