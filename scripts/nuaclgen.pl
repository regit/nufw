#!/usr/bin/perl -w
###################################################################################
#
# nuaclgen.pl : insertion of ACls in the Nu Ldap tree.
#
# Copyright(C) 2003 Eric Leblond <eric@regit.org>
#		     Vincent Deffontaines <vincent@gryzor.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
###################################################################################

use Net::LDAP;
use Getopt::Long;
use Socket;
$Getopt::Long::ignorecase=0;

my %acl_hash;

# include conf variables
require("/etc/nufw/nuaclgen.conf");



sub convert_addr {
  my @list;
  my $partsum;
  my @parts;
  foreach $address (@_) {
    @parts=split /\./, $address;
    $partsum=0;
    foreach $part (@parts) {
      $partsum = $partsum*256 + $part;
    }
    push @list, ($partsum);
  }
  return @list if @list > 1;
  return $list[0] if @list == 1;
}

sub construct_addr_range {
  my ($range, $src , $dst);
  
  $range=shift;
  if ($range=~m#([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/([0-9]{1,2})#){
    return (convert_addr($1),convert_addr($1)+2**(32-$2)-1)
  } elsif ( $range=~m/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ){
    my $ip=convert_addr($range);
    return ($ip,$ip);
  } else {
    return "Invalid";
  }
}

sub construct_port_range {
  my @range =  split /:/ , shift;
  if (scalar @range == 2){
    return @range;
  } elsif (scalar @range == 1) {
    return ($range[0], $range[0]);
  } else {
    return "OOPs";
  }
}

$result = GetOptions("saddr=s" => \$saddr,
		     "daddr=s" => \$daddr,
		     "proto=i" => \$proto,
		     "sport=i" => \$sport,
		     "dport=i" => \$dport,
		     "jump=s" => \$decision,
		     "groups=s" => \$groups,
		     "Aclname=s" => \$aclname
		    );

if ($result == 0){
  die "Error parsing options\n";
}
if (not defined($saddr)){
  $saddr="0.0.0.0/0";
} 
($acl{"SrcIpStart"},$acl{"SrcIpEnd"})=construct_addr_range($saddr);

if (not defined($daddr)){
  $daddr="0.0.0.0/0";
}
($acl{"DstIpStart"},$acl{"DstIpEnd"})=construct_addr_range($daddr);

if (not defined($sport)){
  $sport="0:65536";
}
($acl{"SrcPortStart"},$acl{"SrcPortEnd"})=construct_port_range($sport);

if (not defined($dport)){
  $dport="0:65536";
}
($acl{"DstPortStart"},$acl{"DstPortEnd"})=construct_port_range($dport);

if (not defined($decision)){
  die "No decision given\n";
} else {
  if ($decision eq "ACCEPT") {
    $acl{"Decision"}=1;
  } else {
    $acl{"Decision"}=0;
  }
}

if (not defined($proto)){
  $acl{"Proto"}=[6,17];
} else {
  $acl{"Proto"}=$proto;
}


if (not defined($groups)){
  die "No group(s) given\n";
} else {
  if ($groups=~m/,/) {
    $acl{"Group"}= [split /,/ , $groups];
  } else {
     $acl{"Group"}= $groups;
}

}


$acl{"objectclass"}  = [ "top", "NuAccessControlList" ];

if (not defined($aclname)){
  die "No Acl Name given, Aborting\n";
} 

$aclname=~m/^cn=(\w+),.*/ and $acl{"cn"}=$1;

#foreach $item (keys %acl) {
#  print $item.": ".$acl{$item}."\n";
#}

#do ldap add
$ldap = Net::LDAP->new($ldap_host)  or die $@;;
# bind to a directory with dn and password
$result = $ldap->bind ( $username,
	      password => $password
	    )  or die $@;
 $result->code && warn "failed to bind: ", $result->error;
print "Adding $aclname\n";
$result = $ldap->add( $aclname,
		      attr => [%acl ]) ;

$result->code && warn "failed to add entry: ", $result->error or print "done\n";

$ldap->unbind;  # take down session




