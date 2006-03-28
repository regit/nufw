#ifndef DOCUMENTATION_H
#define DOCUMENTATION_H

/**
 * \mainpage NuFW documentation (SVN version)
 *
 * \section intro_sec Introduction
 *
 * NuFW is a firewall based on NetFilter (http://www.netfilter.org)
 * which authentificate users. It's composed of three parts:
 *   - NuFW: gateway working directly with NetFilter, just send new
 *     connection packets to NuAuth, and apply decision (accept or drop) ;
 *   - NuAuth: Kernel of the firewall, manage client connections, and take
 *     decision on new connection packets send by NuFW ;
 *   - Client (nutcpc or Windows client): Authentificate himself to NuAuth and
 *     answer to NuAuth request (send its new connection list).
 *
 * This documentation only describe NuFW and NuAuth.
 * 
 * \section nufw_sec NuFW
 *
 * NuFW is a very simple gateway. It's running in user-space but need root
 * account because it's connected directly to NetFilter using IPQ or Netfilter
 * queue link.
 *
 * NuFW is composed of three main parts:
 *    - Main process which just display audit informations (number of received
 *      packet and number of accepted packets) every five seconds ; 
 *    - Packet server thread: packetsrv() ;
 *    - Auth server thread (connection to NuAuth): authsrv().
 *
 * \section nuauth_sec NuAuth
 *
 * NuAuth is the biggest and most important part of NuFW firewall:
 *    - Main loop: nuauth_main_loop()
 */

#endif  /* of ifndef DOCUMENTATION_H */

