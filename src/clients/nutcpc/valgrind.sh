#!/bin/sh

NUTCPC=.libs/nutcpc
NUTCPC_ARGS="-H localhost -U haypo -d"

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
    
# Some interesting options:
#    --gen-suppressions=yes
#    --gen-suppressions=yes \

# Explains:
#   --run-libc-freeres=no: Valgrind free all memory that libc allocates

valgrind \
    --show-reachable=yes -v \
    --suppressions=valgrind.supp \
    --log-file-exactly=$LOG \
    --run-libc-freeres=no \
    --leak-check=full \
    --verbose \
    $NUTCPC $NUTCPC_ARGS 2>&1

trap - SIGINT SIGTERM

echo
echo "Quit Valgrind."

