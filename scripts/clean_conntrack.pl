#!/usr/bin/perl -w
#
## fwcon.pl: Forward "open" connection to actif table.
#
# Copyright(C) 2003-2005 INL
# Written by Thomas Sabono <thomas@inl.fr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#


use strict;
use DBI;

my $mysql_user="root";
my $mysql_pass="";
my $mysql_host="localhost";
my $mysql_database="ulogd";
my $actif_table="conntrack_ulog";
my $archive_table="ulog";

my $mysql_rows="raw_mac, oob_time_sec, oob_time_usec, oob_prefix, oob_mark, oob_in, oob_out,
		ip_saddr, ip_daddr, ip_protocol, ip_tos, ip_ttl, ip_totlen, ip_ihl, ip_csum,
		ip_id, ip_fragoff, tcp_sport, tcp_dport, tcp_seq, tcp_ackseq, tcp_window,
		tcp_urg, tcp_urgp, tcp_ack, tcp_psh, tcp_rst, tcp_syn, tcp_fin, udp_sport,
		udp_dport, udp_len, icmp_type, icmp_code, icmp_echoid, icmp_echoseq, icmp_gateway,
		icmp_fragmtu, pwsniff_user, pwsniff_pass, ahesp_spi, timestamp, state, end_timestamp,
		start_timestamp, username, user_id, client_os, client_app";

#
## Database initialisation.
#
my $mysql_connection="DBI:mysql:database=$mysql_database;host=$mysql_host";
my $dbh = DBI->connect($mysql_connection, $mysql_user, $mysql_pass)
	or die "[!] Couldn't connect to database: " . DBI->errstr;
my $drh = DBI->install_driver("mysql");

#
## Get greater id.
#
my $sth = $dbh->prepare("SELECT id FROM $actif_table WHERE state = 0 OR state = 3 ORDER BY id DESC
	LIMIT 1");
$sth->execute or die "[!] Couldn't execute statement: " . $sth->errstr;

my @buffer = $sth->fetchrow_array;
my $max_id = $buffer[0] ? $buffer[0] : 0;

#
## Execute update query.
#
$sth = $dbh->prepare("INSERT INTO $archive_table($mysql_rows)
	SELECT $mysql_rows FROM $actif_table WHERE id <= $max_id AND (state = 0 OR state = 3)");
$sth->execute or die "[!] Couldn't execute statement: " . $sth->errstr;

#
## Delete old value from actif table.
#
$sth = $dbh->prepare("DELETE FROM $actif_table WHERE id <= $max_id AND (state=0 OR state=3)");
$sth->execute or die "[!] Couldn't execute statement: " . $sth->errstr;
