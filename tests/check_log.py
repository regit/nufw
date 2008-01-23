#!/usr/bin/python
#
# Check log helps you to enforce a decent
# log method into your program
# Written by Sebastien Tricaud 2008
# $Id$
#

# Config
log_functions = ['log_area_printf','g_warning','log_message']

import sys
import sre

def main():

        if len(sys.argv) < 2:
                print "Syntax: %s file.c" % (sys.argv[0])
                sys.exit(1)


        block = 0
        line_nb = 0
        log_func = 0

        file = open(sys.argv[1], "r")

        for line in file:
                line_nb += 1

                if block == 0:
                        log_func = 0

                if sre.match(".*return.*", line):
                        if block > 1 and log_func == 0:
                                print "%s:%d:%s : return called but no log previously defined, this might confuse the user." % (sys.argv[1], line_nb, line.strip())

                if sre.match(".*{.*", line):
                        block += 1

                if sre.match(".*}.*", line):
                        block -= 1
                        log_func = 0

                for log in log_functions:
                        expr = ".*%s.*" % (log)
                        if sre.match(expr, line) and block > 0 :
                                log_func = 1


        file.close()

if __name__ == "__main__":
        main()

