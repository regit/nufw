/*
 * libnuclient - TCP/IP connection auth client library.
 *
 * Copyright 2004-2006 - INL
 *	written by Eric Leblond <regit@inl.fr>
 *	           Vincent Deffontaines <vincent@inl.fr>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef LIBNUCLIENT_H
#define LIBNUCLIENT_H

#include "nuclient.h"

void nu_exit_clean(NuAuth * session);

int compare (NuAuth *session,conntable_t *old, conntable_t *new, nuclient_error *err);

void do_panic(const char *filename, unsigned long line, const char *fmt, ...);

/** 
 * \def panic(format, ...)
 * 
 * Call do_panic(__FILE__, __LINE__, format, ...) 
 */
#define panic(format, args...) \
    do_panic(__FILE__, __LINE__, format, ##args )

/** 
 * \def nu_assert(test, format, ...)
 * 
 * If test fails, call do_panic(__FILE__, __LINE__, format, ...) 
 */
#define nu_assert(test, format, args...) \
    do { if (!(test)) do_panic(__FILE__, __LINE__, format, ##args ); } while (0)

void ask_session_end(NuAuth* session);

#endif

