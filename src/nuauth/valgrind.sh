#!/bin/sh

echo "Run nuauth in Valgrind"
echo
echo "!!! Valgrind makes NuAuth very slow, system auth. doesn't work because of timeouts."
echo "!!! Use NuAuth with plaintext auth"
echo

LOG=valgrind.log
NUAUTH_OPT=-vvvvvvvvvvvvvvv

function stop_valgrind
{
    echo "NuAuth in Valgrind stopped with CTRL+C"
    echo "Output written in file $LOG"
}    

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
    ./nuauth $NUAUTH_OPT 2>&1

trap - SIGINT SIGTERM

echo "Quit."
