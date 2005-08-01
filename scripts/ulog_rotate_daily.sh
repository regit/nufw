#!/bin/bash
SQLCMD="mysql ulogd"
TABNAME=ulog;
#SQLCMD="echo"
echo "insert into ${TABNAME}_1  select * from $TABNAME where timestamp < CURDATE() - INTERVAL 7 DAY;
delete from $TABNAME where  timestamp < CURDATE() - INTERVAL 7 DAY;
optimize table $TABNAME;"  | $SQLCMD
