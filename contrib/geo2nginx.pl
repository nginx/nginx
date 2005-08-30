#!/usr/bin/perl -w

# (c) Andrei Nigmatulin, 2005
#
# this script provided "as is", without any warranties. use it at your own risk.
#
# special thanx to Andrew Sitnikov for perl port
#
# this script converts CSV geoip database (free download at http://www.maxmind.com/app/geoip_country)
# to format, suitable for use with nginx_http_geo module (http://sysoev.ru/nginx)
#
# for example, line with ip range
#
#   "62.16.68.0","62.16.127.255","1041253376","1041268735","RU","Russian Federation"
#
# will be converted to four subnetworks:
#
#   62.16.68.0/22 RU;
#   62.16.72.0/21 RU;
#   62.16.80.0/20 RU;
#   62.16.96.0/19 RU;


use warnings;
use strict;

while( <STDIN> ){
	if (/"[^"]+","[^"]+","([^"]+)","([^"]+)","([^"]+)"/){
		print_subnets($1, $2, $3);
	}
}

sub  print_subnets {
	my ($a1, $a2, $c) = @_;
	my $l;
    while ($a1 <= $a2) {
		for ($l = 0; ($a1 & (1 << $l)) == 0 && ($a1 + ((1 << ($l + 1)) - 1)) <= $a2; $l++){};
		print long2ip($a1) . "/" . (32 - $l) . " " . $c . ";\n";
    	$a1 += (1 << $l);
	}
}

sub long2ip {
	my $ip = shift;

	my $str = 0;

	$str = ($ip & 255);

	$ip >>= 8;
	$str = ($ip & 255).".$str";

	$ip >>= 8;
	$str = ($ip & 255).".$str";

	$ip >>= 8;
	$str = ($ip & 255).".$str";
}
