/*
** Copyright 2006-2009 -INL
** Written by Victor Stinner <haypo@inl.fr>
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

#ifndef DOCUMENTATION_H
#define DOCUMENTATION_H

/**
 * \mainpage NuFW documentation (SVN version)
 *
 * \section intro_sec Introduction
 *
 * NuFW is a firewall based on NetFilter (http://www.netfilter.org)
 * which authenticate users. It's composed of three parts:
 *   - NuFW: gateway that works directly with NetFilter, just sends new
 *     connection packets to NuAuth, and applies decisions (accept or drop) ;
 *   - NuAuth: Kernel of the firewall, manages client connections, and takes
 *     decisions on new connection packets sent by NuFW ;
 *   - Client (nutcpc or Windows client): Authenticates users to NuAuth and
 *     answers NuAuth requests (sends its new connection list).
 *
 * This documentation only describes four parts: NuFW, NuAuth, libnuclient and nutcpc.
 * 
 * \section nufw_sec NuFW
 *
 * NuFW is a very simple gateway. It runs in user-space but needs root
 * privileges because it's connected directly to NetFilter using IPQ or Netfilter
 * queue link.
 *
 * NuFW is composed of three main parts:
 *    - Main process which just displays audit informations (number of received
 *      packets and number of accepted packets) every five seconds ; 
 *    - Packet server thread: packetsrv() ;
 *    - Auth server thread (connection to NuAuth): authsrv().
 *
 * \section nuauth_sec NuAuth
 *
 * NuAuth is the biggest and most important part of NuFW firewall:
 *    - Create all queues and threads: init_nuauthdatas()
 *    - Main loop: nuauth_main_loop()
 *
 * \section client_sec Client
 * \subsection libnuclient_sec Libnuclient
 *
 * Libnuclient is a library used by nuauth on client side to read active
 * connection. The library is used by nutcpc client. Public API is
 * defined in file nuclient.h.
 *
 * To initialize the library, use:
\verbatim
NuAuth *session = NULL;
struct nuclient_error nuerror;
nu_client_global_init(&nuerror);
session = nu_client_init2(
           "hostname", "4129",
           NULL, NULL,
           &get_username, &get_password,  NULL,
           &nuerror);
\endverbatim
 *
 * \subsection nutcpc_sec nutcpc client 
 *
 * Nutcpc is the Linux and FreeBSD command line client. 
 */

#endif				/* of ifndef DOCUMENTATION_H */
