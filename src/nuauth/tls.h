/*
** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
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

#include <gcrypt.h>
#ifdef G_THREADS_IMPL_POSIX
//#warning "this may be a source of problems"
#include <pthread.h>
#ifndef GCRY_THREAD
#define GCRY_THREAD 1
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif
#else
#error "Code need to be written to have gcrypt support other threading type"
#endif



#define KEYFILE "privkey.pem"
#define CERTFILE "cacert.pem"
#define CAFILE "/etc/nufw/cacert.pem"
#define CRLFILE "/etc/nufw/crl.pem"

#define MAX_BUF 1024
#define DH_BITS 1024

#define NB_AUTHCHECK 10

GAsyncQueue* mx_queue;
GAsyncQueue* mx_nufw_queue;

int tls_connect(int c,gnutls_session** session_ptr);
