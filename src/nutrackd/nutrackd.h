#include <config.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <time.h>

#include "nutrackd_debug.h"

#define PACKET_TIMEOUT 15
#define SHORT_REQUEST_SIZE 256
#define LONG_REQUEST_SIZE 512

//WARNING : this is also defined in nuauth/connections.h, which sucks
#define STATE_CLOSE 0x3

int update_sql_table(u_int32_t src, u_int32_t dst, u_int8_t proto, u_int16_t sport, u_int16_t dport);
void sql_close(void);
