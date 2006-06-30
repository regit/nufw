#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

/**
 * Use Posix standard, version "IEEE Std 1003.1b-1993" 
 * Neded by sigaction (signal.h) and timespec (time.h) for example
 */
#define _POSIX_C_SOURCE 199309L

/**
 * Use 4.3BSD standard, needed to get 'tcphdr' structure. 
 */
#define _BSD_SOURCE

#include <netinet/in.h>

#ifdef TRACKING_WITH_PAYLOAD
#  define PAYLOAD_SAMPLE 8
#  define PAYLOAD6_SAMPLE PAYLOAD_SAMPLE
#endif

/** State of a connection */
typedef enum
{
    TCP_STATE_DROP = 0,    /*!< NuAuth decide to drop the connection */
    TCP_STATE_OPEN,        /*!< A new connection is just created (SYN) */
    TCP_STATE_ESTABLISHED, /*!< The connection is established (SYN,ACK) */
    TCP_STATE_CLOSE,       /*!< The connection is closed (RST) */
    TCP_STATE_UNKNOW       /*!< Error code of get_tcp_headers() function */
} tcp_state_t;

/**
 * Informations about an IPv4 connection used as key for connection
 * identification.
 */
typedef struct {
  /* Group informations about destination to make
   * ACL hash function faster. If you change this
   * structure, please also change hash_acl() and hash_connection() */
  struct in6_addr saddr;    /*!< IPv6 source address */
  struct in6_addr daddr;    /*!< IPv6 destination address */
  u_int8_t protocol;        /*!< IP protocol */
  u_int8_t padding;         /*!< Padding to 32 bits alignment */
  u_int16_t dest;           /*!< TCP/UDP destination port */

  u_int16_t source;         /*!< TCP/UDP source port */
  u_int8_t type;            /*!< ICMP message type */
  u_int8_t code;            /*!< ICMP code type */
#ifdef TRACKING_WITH_PAYLOAD
  char payload[PAYLOAD_SAMPLE];  /*!< First 8 bytes of protocol payload used for ICMP reject */
#endif
} tracking_t;

unsigned int get_ip_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size);
int get_udp_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size);
tcp_state_t get_tcp_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size);
int get_icmp_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size);
int get_icmpv6_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size);

#endif

