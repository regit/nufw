#!/bin/bash

DATABASENAME="ulogd";
MYSQL_VERSION="5";

SQLCMD="mysql $DATABASENAME";
declare -i TABNUMBER=52;
TABNAME=ulog;
TABLIST="$TABNAME offenders usersstats users tcp_ports udp_ports"
#set -x
#SQLCMD="true"

# delete tables TABNUMBER
for TABLE in $TABLIST; do 
    echo "drop table IF EXISTS ${TABLE}_$TABNUMBER;" | $SQLCMD;
done;
# move table from 11 to 2
declare -i NEXT;
for ((TABLE=$(($TABNUMBER-1));$TABLE>=1;TABLE--)); do 
    NEXT=$(($TABLE+1))
    for TABLEITEM in $TABLIST; do
        echo "rename table ${TABLEITEM}_$TABLE to ${TABLEITEM}_$NEXT" | $SQLCMD 2>/dev/null
    done
done
#compress 2
cd /var/lib/mysql/$DATABASENAME/
myisampack -s ${TABNAME}_2.MYI
myisamchk -s -rq /var/lib/mysql/$DATABASENAME/${TABNAME}_2.MYI


if [ $MYSQL_VERSION == "5" ]; then
	for TABLE in $TABLIST; do 
		echo "CREATE TABLE ${TABLE}_1 LIKE ${TABLE};" | $SQLCMD;
	done
else
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
	KEY user_id (user_id),
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

	echo "CREATE TABLE usersstats_1 (
	user_id smallint(5) unsigned default NULL,
	username varchar(30) default NULL,
	bad_conns int(10) unsigned not NULL default '0',
	good_conns int(10) unsigned not NULL default '0',
	first_time int(10) unsigned default NULL,
	last_time int(10) unsigned default NULL,
	PRIMARY KEY  (user_id),
	KEY username (username)
	) TYPE=MyISAM;
	" | $SQLCMD

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

	echo "CREATE TABLE users_1 (
	ip_saddr int(10) unsigned NOT NULL,
	socket int(10) unsigned NOT NULL,
	user_id int(10) unsigned default NULL,
	username varchar(30) default NULL,
	start_time DATETIME default NULL,
	end_time DATETIME default NULL,
	os_sysname varchar(40) default NULL,
	os_release varchar(40) default NULL,
	os_version varchar(100) default NULL,
	KEY socket (socket),
	KEY ip_saddr (ip_saddr),
	KEY username (username)
	) TYPE=MyISAM;
	" | $SQLCMD

fi



cd $DIR
