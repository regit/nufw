#!/bin/bash

NUTCPC=.libs/nutcpc
NUTCPC_ARGS="-H 192.168.0.2 -U haypo -P haypo -d"

echo "Run nutcpc in Valgrind"
echo

LOG=valgrind.log

function stop_valgrind
{
    echo "NuAuth in Valgrind stopped with CTRL+C"
    echo "Output written in file $LOG"
}

USER=haypo
NUAUTH_PATH=/home/haypo/inl/trunk
CLIENT=$NUAUTH_PATH/src/clients
export LD_LIBRARY_PATH=$CLIENT/lib/.libs

trap stop_valgrind SIGINT SIGTERM

export G_SLICE=always-malloc

if [ -d /usr/lib/debug ]; then
   export LD_LIBRARY_PATH=/usr/lib/debug:$LD_LIBRARY_PATH
   if [ -e /usr/lib/debug/libdl-2.4.so ]; then
      export LD_PRELOAD=/usr/lib/debug/libdl-2.4.so
   fi
else
   echo "VALGRIND WARNING: /usr/lib/debug directory is missing, install libc6-dbg"
fi

echo "Run \"$NUTCPC $NUTCPC_ARGS\"..."
valgrind \
    --show-reachable=yes -v \
    --suppressions=valgrind.supp \
    --log-file-exactly=$LOG \
    --run-libc-freeres=yes \
    --leak-check=full \
    --verbose \
    $NUTCPC $NUTCPC_ARGS 2>&1

trap - SIGINT SIGTERM

echo
echo "Quit Valgrind."

