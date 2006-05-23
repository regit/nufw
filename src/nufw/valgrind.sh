#!/bin/sh

echo "Run nuauth in Valgrind"
echo
echo "!!! Valgrind makes NuAuth very slow, system auth. doesn't work because of timeouts."
echo "!!! Use NuAuth with plaintext auth"
echo

LOG=valgrind.log
NUFW_OPT=-vv

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
 
# Disabled:
#    --suppressions=valgrind.supp \

sudo valgrind \
    --show-reachable=yes -v \
    --log-file-exactly=$LOG \
    --run-libc-freeres=yes \
    --leak-check=full \
    --verbose \
    ./nufw $NUFW_OPT 2>&1

trap - SIGINT SIGTERM

echo "Quit valgrind.sh"
