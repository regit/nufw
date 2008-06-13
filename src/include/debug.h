/*
** Copyright 2005-2008 - INL
** Written by Vincent Deffontaines <vincent@gryzor.com>
**            Victor Stinner <haypo@inl.fr>
** INL http://www.inl.fr/
**
** $Id$
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, version 3 of the License.
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

#ifndef NUFW_DEBUG_HEADER
#define NUFW_DEBUG_HEADER


#define RETURN_NO_LOG return

/**
 * Debug levels: default is #DEFAULT_DEBUG_LEVEL
 * and values are between #MIN_DEBUG_LEVEL and #MAX_DEBUG_LEVEL
 */
typedef enum {
	DEBUG_LEVEL_FATAL = 1,	/*!< 1: Least verbose level */
	DEBUG_LEVEL_CRITICAL,	/*!< 2 */
	DEBUG_LEVEL_SERIOUS_WARNING,	/*!< 3 (default) */
	DEBUG_LEVEL_WARNING,	/*!< 4 */
	DEBUG_LEVEL_SERIOUS_MESSAGE,	/*!< 5 */
	DEBUG_LEVEL_MESSAGE,	/*!< 6 */
	DEBUG_LEVEL_INFO,	/*!< 7 */
	DEBUG_LEVEL_DEBUG,	/*!< 8 */
	DEBUG_LEVEL_VERBOSE_DEBUG,	/*!< 9: Most verbose level */

	DEFAULT_DEBUG_LEVEL = DEBUG_LEVEL_SERIOUS_WARNING,	/*!< Default debug level */

	MIN_DEBUG_LEVEL = DEBUG_LEVEL_FATAL,	/*!< Minimum debug level value (least verbose) */
	MAX_DEBUG_LEVEL = DEBUG_LEVEL_VERBOSE_DEBUG	/*!< Maximum debug level value (most verbose) */
} debug_level_t;

/** Debug areas (domains), default is #DEFAULT_DEBUG_AREAS (all) */
typedef enum {
	DEBUG_AREA_MAIN = 1,	/*!< 1: Main domain */
	DEBUG_AREA_PACKET = 2,	/*!< 2: Packet domain */
	DEBUG_AREA_USER = 4,	/*!< 4: User domain */
	DEBUG_AREA_GW = 8,	/*!< 8: Gateway domain */
	DEBUG_AREA_AUTH = 16,	/*!< 16: Auth. domain */
	DEBUG_AREA_PERF = 32,	/*!< 32: Performance display domain */

	DEBUG_AREA_ALL = DEBUG_AREA_MAIN | DEBUG_AREA_PACKET | DEBUG_AREA_USER
		| DEBUG_AREA_GW | DEBUG_AREA_AUTH | DEBUG_AREA_PERF,	/*!< All debug areas */

	DEFAULT_DEBUG_AREAS = DEBUG_AREA_MAIN | DEBUG_AREA_PACKET | DEBUG_AREA_USER
		| DEBUG_AREA_GW | DEBUG_AREA_AUTH	/*!< Default debug areas: all areas but not perf*/
} debug_area_t;

#define LOG_FACILITY LOG_DAEMON

#endif				/* define NUFW_DEBUG_HEADER */
