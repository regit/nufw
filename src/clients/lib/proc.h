/*
 ** Copyright 2005 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
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


#ifndef PROC_H
#define PROC_H

#define PROGNAME_WIDTH 64
#define PROGNAME_BASE64_WIDTH (PROGNAME_WIDTH*2)

#ifdef LINUX

#define PRG_HASH_SIZE 211

int prg_cache_loaded;


void prg_cache_load(void);
const char *prg_cache_get(unsigned long inode);
const char *prg_cache_getsig(int algo, unsigned long inode);
void prg_cache_clear(void);
#endif

#endif
