#!/bin/bash
SQLCMD="mysql ulogd"
TABNAME=ulog;
USERTABNAME=users;
#SQLCMD="echo"
echo "insert into ${TABNAME}_1  select * from $TABNAME where timestamp < CURDATE() - INTERVAL 7 DAY;
delete from $TABNAME where  timestamp < CURDATE() - INTERVAL 7 DAY;
optimize table $TABNAME;"  | $SQLCMD

echo "insert into ${USERTABNAME}_1  select * from $USERTABNAME where end_time is NOT NULL AND end_time < CURDATE() - INTERVAL 7 DAY;
delete from $USERTABNAME where  end_time IS NOT NULL AND end_time < CURDATE() - INTERVAL 7 DAY;
optimize table $USERTABNAME;"  | $SQLCMD
