#include <config.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <conntrack.h>

#include "nutrackd_debug.h"

//Not clever to redefine these here.
#define TCP 6
#define UDP 17

#define PACKET_TIMEOUT 15
