#!/bin/bash

echo "Run nuauth in Valgrind"
echo
echo "!!! Valgrind makes NuAuth very slow, system auth. doesn't work because of timeouts."
echo "!!! Use NuAuth with plaintext auth"
echo

LOG=valgrind.log

function stop_valgrind
{
    echo "NuAuth in Valgrind stopped with CTRL+C"
    echo "Output written in file $LOG"
}

trap stop_valgrind SIGINT SIGTERM

# glib don't use slices, use classic malloc() instead
# so Valgrind is able to match memory leaks
export G_SLICE=always-malloc

# Some interesting options:
#    --gen-suppressions=yes
#    --gen-suppressions=yes \

# Explains:
#   --run-libc-freeres=no: Valgrind free all memory that libc allocates

if [ -d /usr/lib/debug ]; then
   export LD_LIBRARY_PATH=/usr/lib/debug:$LD_LIBRARY_PATH
   if [ -e /usr/lib/debug/libdl-2.4.so ]; then
      export LD_PRELOAD=/usr/lib/debug/libdl-2.4.so
   fi
else
   echo "VALGRIND WARNING: /usr/lib/debug directory is missing, install libc6-dbg"
fi

valgrind \
    --show-reachable=yes -v \
    --suppressions=valgrind.supp \
    --log-file-exactly=$LOG \
    --run-libc-freeres=no \
    --leak-check=full \
    --verbose \
    ./nuauth "$@" 2>&1

unset LD_PRELOAD LD_LIBRARY_PATH

trap - SIGINT SIGTERM

echo "Quit."
