/*
 ** Copyright(C) 2007 INL
 ** Written by Victor Stinner <victor.stinner@inl.fr>
 **
 ** $Id: command.h 2738 2007-02-17 13:59:56Z regit $
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


#ifndef COMMAND_CODEC_H
#define COMMAND_CODEC_H

#define BYTECODE_INT32 'i'
#define BYTECODE_INT64 'I'
#define BYTECODE_IPV6 'p'
#define BYTECODE_STRING 's'
#define BYTECODE_TUPLE '('

#define BYTECODE_ANSWER 'a'
#define BYTECODE_USER 'u'
#define BYTECODE_UPTIME 'U'

#endif /* COMMAND_CODEC_H */

