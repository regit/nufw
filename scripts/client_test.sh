#!/bin/bash

NUTCPC_PATH=src/clients/nutcpc/
NUAUTH_HOST=192.168.33.229
USER=user
PASS=imauser


function check
{
	echo -n "$2"
	OUT="$(eval $1 2>&1)"
	RET=$?
	
	if [ $RET == 0 ]
	then
		echo $'\t'$'\t'"[  Ok  ]"
		return 0
	else
		echo $'\t'$'\t'"[Failed]"
		echo "$OUT"
		kill -9 $NUTCPC_PID
		exit 1
	fi
}

function nut_pgrep
{
	ps xwww|grep "$1"|awk '{print $1}'
}

function nut_netstat
{
	# escape '.' in $NUAUTH_HOST:
	GREP_HOST="$(echo $NUAUTH_HOST | sed -e 's/\./\\./g')"

	case "$(uname)" in
		"Darwin") eval netstat -np tcp|grep "$GREP_HOST\\.4129[ ]*ESTABLISHED" ;;
		"FreeBSD") eval netstat -np tcp|grep "$GREP_HOST\\.4129[ ]*ESTABLISHED" ;;
		"Linux") eval netstat -tanp|grep ESTABLISHED$NUTCPC_PID/ ;;
		*) echo "Non-spported OS" > /dev/stderr && exit 1 ;;
	esac
}

cd "$NUTCPC_PATH"
./nutcpc -l -H "$NUAUTH_HOST" -U "$USER" -P "$PASS" -d 2>&1 >/dev/null &
NUTCPC_PID=$!

# Give nutcpc some time to connect
sleep 5

check "(nut_pgrep lt-nutcpc ; nut_pgrep nutcpc) | grep $NUTCPC_PID" "Nutcpc running"
check "nut_netstat" "Nutcpc connected to Nuauth"
check "curl -s --connect-timeout 5 http://$NUAUTH_HOST:80/ >/dev/null" "Packet authentication"

kill -9 $NUTCPC_PID

