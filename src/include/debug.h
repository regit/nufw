/*
**
** Written by Vincent Deffontaines <vincent@gryzor.com>
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




// DEBUG_LEVEL's value is 1 to 8

#define DEBUG_LEVEL_FATAL		1
#define DEBUG_LEVEL_CRITICAL		2
#define DEBUG_LEVEL_SERIOUS_WARNING	3
#define DEBUG_LEVEL_WARNING		4
#define DEBUG_LEVEL_SERIOUS_MESSAGE	5
#define DEBUG_LEVEL_MESSAGE		6
#define DEBUG_LEVEL_INFO		7
#define DEBUG_LEVEL_DEBUG		8
#define DEBUG_LEVEL_VERBOSE_DEBUG	9

#define DEFAULT_DEBUG_LEVEL		DEBUG_LEVEL_SERIOUS_WARNING

#define MIN_DEBUG_LEVEL			DEBUG_LEVEL_CRITICAL
#define MAX_DEBUG_LEVEL			DEBUG_LEVEL_VERBOSE_DEBUG

#define DEBUG_AREA_MAIN		1
#define DEBUG_AREA_PACKET	2
#define DEBUG_AREA_USER		4
#define DEBUG_AREA_GW		8
#define DEBUG_AREA_AUTH		16

/* Default is to debug all*/
#define DEFAULT_DEBUG_AREAS DEBUG_AREA_MAIN||DEBUG_AREA_PACKET||DEBUG_AREA_USER||DEBUG_AREA_GW||DEBUG_AREA_AUTH

#define LOG_FACILITY LOG_DAEMON

#define DEBUG_OR_NOT(LOGLEVEL,LOGAREA) (LOGAREA&&debug_areas)&&(debug_level>=LOGLEVEL)

