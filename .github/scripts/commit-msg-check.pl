#!/usr/bin/env perl

# Copyright (C) Nginx, Inc.

#
# Takes input in the form
#
#   git show -s --format=%B <hash>
#

use strict;
use warnings;

my $E = "❌ ";

# 72 characters is a natural choice. It provides 4 characters of
# left/right margin on a standard 80 character wide terminal in
# git-log(1) etc standard output.
#
# vim(1) (from 7.2) ships with Tim Pope's vim-git ftplugin which
# amongst other things autowraps lines when editing commit messages
# after 72 characters.
my $LINE_LENGTH_LIMIT = 72;

my $subject = <>;
my $body;

while (<>) {
	$body .= $_;
}

sub chk_sub_length {
	if (length($subject) > $LINE_LENGTH_LIMIT) {
		print $E . "Subject is longer than " . $LINE_LENGTH_LIMIT .
		      " characters\n";
	}
}

sub chk_sub_prefix_cap {
	my $excemptions = qr/gRPC: /;

	if ($subject =~ /^[a-z][a-zA-Z_-]*: /) {
		if ($subject =~ /^((?!$excemptions).)*$/) {
			print $E . "Subject prefix should be capitalised\n";
		}
	}

	if ($subject =~ /^[a-zA-Z_-]*: [A-Z]/) {
		print $E . "First word after the prefix should be lower case\n";
	}
}

sub chk_body_blank_line {
	if (($body =~ /^(.*)/)[0]) {
		print $E . "Commit message body should be separated from the subject by a blank line\n";
	}
}

sub chk_body_trailers {
	my $prev_line = "";

	foreach (split(/\n/, $body)) {
		if (/^[a-zA-Z-]*: /) {
			if ($prev_line ne "") {
				print $E . "Commit tags/trailers should be separated from the commit message body by a blank line\n";
			}

			last;
		}

		$prev_line = $_;
	}
}

sub chk_body_line_length {
	foreach (split(/\n/, $body)) {
		# Ignore indented lines for command/log output etc and URLs.
		if (/^[ \t]/ || /https?:\/\// || /ftp:\/\//) {
			next;
		}

		# Stop after hitting commit tags/trailers
		if (/^[a-zA-Z-]*: /) {
			last;
		}

		if (length($_) <= $LINE_LENGTH_LIMIT) {
			next;
		}

		print $E . "One or more body lines exceed " . $LINE_LENGTH_LIMIT . " characters. (Indent command/log output etc lines to quell this error)\n";

		last;
	}
}

chomp($subject);
chk_sub_length();
chk_sub_prefix_cap();

chk_body_blank_line();
chk_body_trailers();
chk_body_line_length();
