#!/bin/bash

echo "Run nuauth in Valgrind"
echo
echo "!!! Valgrind makes NuAuth very slow, system auth. doesn't work because of timeouts."
echo "!!! Use NuAuth with plaintext auth"
echo

LOG=valgrind.log

function stop_valgrind
{
    echo "Interrupt nufw (in Valgrind) with CTRL+C."
    echo "Output written in file $LOG"
}

trap stop_valgrind SIGINT SIGTERM

# Some interesting options:
#    --gen-suppressions=yes
#    --gen-suppressions=yes \

# Explains:
#   --run-libc-freeres=no: Valgrind free all memory that libc allocates

# Disabled:
#    --suppressions=valgrind.supp \

if [ -d /usr/lib/debug ]; then
   export LD_LIBRARY_PATH=/usr/lib/debug:$LD_LIBRARY_PATH
   if [ -e /usr/lib/debug/libdl-2.4.so ]; then
      export LD_PRELOAD=/usr/lib/debug/libdl-2.4.so
   fi
else
   echo "VALGRIND WARNING: /usr/lib/debug directory is missing, install libc6-dbg"
fi

sudo valgrind \
    --show-reachable=yes -v \
    --log-file-exactly=$LOG \
    --run-libc-freeres=yes \
    --leak-check=full \
    --verbose \
    ./nufw "$@" 2>&1

trap - SIGINT SIGTERM

echo "Quit valgrind.sh"

