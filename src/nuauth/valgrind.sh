#!/bin/sh
echo "Run nuauth in Valgrind"

LOG=valgrind.log
NUAUTH_OPT=-vvvvvvvvvvvvvvv

function stop_valgrind
{
    echo "NuAuth in Valgrind stopped with CTRL+C"
    echo "Output written in file $LOG"
}    

trap stop_valgrind SIGINT SIGTERM
    
# You may prefer to write output in a log:
#    --log-file-exactly=$LOG \

valgrind \
    --show-reachable=yes -v --suppressions=valgrind.supp \
    --leak-check=full \
    ./nuauth $NUAUTH_OPT 2>&1 | tee $LOG

trap - SIGINT SIGTERM

echo "Quit."
