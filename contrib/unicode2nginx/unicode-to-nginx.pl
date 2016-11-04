#!/usr/bin/perl -w

# Convert unicode mappings to nginx configuration file format.

# You may find useful mappings in various places, including
# unicode.org official site:
#
# http://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1251.TXT
# http://www.unicode.org/Public/MAPPINGS/VENDORS/MISC/KOI8-R.TXT

# Needs perl 5.6 or later.

# Written by Maxim Dounin, mdounin@mdounin.ru

###############################################################################

require 5.006;

while (<>) {
	# Skip comments and empty lines

	next if /^#/;
	next if /^\s*$/;
	chomp;

	# Convert mappings

	if (/^\s*0x(..)\s*0x(....)\s*(#.*)/) {
		# Mapping <from-code> <unicode-code> "#" <unicode-name>
		my $cs_code = $1;
		my $un_code = $2;
		my $un_name = $3;

		# Produce UTF-8 sequence from character code;

		my $un_utf8 = join('',
			map { sprintf("%02X", $_) }
			unpack("U0C*", pack("U", hex($un_code)))
		);

		print "    $cs_code  $un_utf8 ; $un_name\n";

	} else {
		warn "Unrecognized line: '$_'";
	}
}

###############################################################################
