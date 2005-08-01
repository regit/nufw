#!/bin/bash
SQLCMD="mysql ulogd";
declare -i TABNUMBER=52;
TABNAME=ulog;
#set -x
#SQLCMD="echo"

# delete table 12
echo "drop table IF EXISTS ${TABNAME}_$TABNUMBER;" | $SQLCMD;
# move table from 11 to 2
declare -i NEXT;
for ((TABLE=$(($TABNUMBER-1));$TABLE>=1;TABLE--)); do 
	NEXT=$(($TABLE+1))
	echo "rename table ${TABNAME}_$TABLE to ${TABNAME}_$NEXT" | $SQLCMD 2>/dev/null
	echo "rename table offenders_$TABLE to offenders_$NEXT" | $SQLCMD 2>/dev/null
	echo "rename table tcp_ports_$TABLE to tcp_ports_$NEXT" | $SQLCMD 2>/dev/null
	echo "rename table udp_ports_$TABLE to udp_ports_$NEXT" | $SQLCMD 2>/dev/null
done
#compress 2
cd /var/lib/mysql/ulogd/
myisampack -s $TABNAME_2.MYI
myisamchk -s -rq /var/lib/mysql/ulogd/$TABNAME_2.MYI

# create table 1

echo "CREATE TABLE ${TABNAME}_1 (
  id int(10) unsigned NOT NULL auto_increment,
  raw_mac varchar(80) default NULL,
  oob_time_sec int(10) unsigned default NULL,
  oob_time_usec int(10) unsigned default NULL,
  oob_prefix varchar(32) default NULL,
  oob_mark int(10) unsigned default NULL,
  oob_in varchar(32) default NULL,
  oob_out varchar(32) default NULL,
  ip_saddr int(10) unsigned default NULL,
  ip_daddr int(10) unsigned default NULL,
  ip_protocol tinyint(3) unsigned default NULL,
  ip_tos tinyint(3) unsigned default NULL,
  ip_ttl tinyint(3) unsigned default NULL,
  ip_totlen smallint(5) unsigned default NULL,
  ip_ihl tinyint(3) unsigned default NULL,
  ip_csum smallint(5) unsigned default NULL,
  ip_id smallint(5) unsigned default NULL,
  ip_fragoff smallint(5) unsigned default NULL,
  tcp_sport smallint(5) unsigned default NULL,
  tcp_dport smallint(5) unsigned default NULL,
  tcp_seq int(10) unsigned default NULL,
  tcp_ackseq int(10) unsigned default NULL,
  tcp_window smallint(5) unsigned default NULL,
  tcp_urg tinyint(4) default NULL,
  tcp_urgp smallint(5) unsigned default NULL,
  tcp_ack tinyint(4) default NULL,
  tcp_psh tinyint(4) default NULL,
  tcp_rst tinyint(4) default NULL,
  tcp_syn tinyint(4) default NULL,
  tcp_fin tinyint(4) default NULL,
  udp_sport smallint(5) unsigned default NULL,
  udp_dport smallint(5) unsigned default NULL,
  udp_len smallint(5) unsigned default NULL,
  icmp_type tinyint(3) unsigned default NULL,
  icmp_code tinyint(3) unsigned default NULL,
  icmp_echoid smallint(5) unsigned default NULL,
  icmp_echoseq smallint(5) unsigned default NULL,
  icmp_gateway int(10) unsigned default NULL,
  icmp_fragmtu smallint(5) unsigned default NULL,
  pwsniff_user varchar(30) default NULL,
  pwsniff_pass varchar(30) default NULL,
  ahesp_spi int(10) unsigned default NULL,
  timestamp timestamp(14) NOT NULL,
  UNIQUE KEY id (id),
  KEY index_id (id),
  KEY timestamp (timestamp),
  KEY ip_saddr (ip_saddr),
  KEY udp_dport (udp_dport),
  KEY tcp_dport (tcp_dport),
  KEY oob_time_sec (oob_time_sec),
  state smallint(6) unsigned default NULL,
  end_timestamp datetime default NULL,
  start_timestamp datetime default NULL,
  username varchar(30) default NULL,
  user_id smallint(5) unsigned default NULL,
  client_os varchar(128) default NULL,
  client_app varchar(128) default NULL
) TYPE=MyISAM;
" | $SQLCMD 

echo "CREATE TABLE offenders_1 (
  ip_addr int(10) unsigned NOT NULL default '0',
  first_time int(10) unsigned default NULL,
  last_time int(10) unsigned default NULL,
  count int(10) default NULL,
  PRIMARY KEY  (ip_addr)
) TYPE=MyISAM;
"  | $SQLCMD

echo "CREATE TABLE tcp_ports_1 (
  tcp_dport smallint(5) unsigned NOT NULL default '0',
  first_time int(10) unsigned default NULL,
  last_time int(10) unsigned default NULL,
  count int(10) default NULL,
  PRIMARY KEY  (tcp_dport),
  KEY last_time (last_time)
) TYPE=MyISAM;
"  | $SQLCMD

echo "CREATE TABLE udp_ports_1 (
  udp_dport smallint(5) unsigned NOT NULL default '0',
  first_time int(10) unsigned default NULL,
  last_time int(10) unsigned default NULL,
  count int(10) default NULL,
  PRIMARY KEY  (udp_dport),
  KEY last_time (last_time)
) TYPE=MyISAM;
" | $SQLCMD

cd $DIR
