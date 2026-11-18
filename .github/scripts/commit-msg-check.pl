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

my @TRAILERS = qw(
	Acked-by
	Assisted-by
	Cc
	Closes
	Co-authored-by
	Debugged-by
	Fixes
	Link
	Message-ID
	Origin
	Related
	Reported-by
	Requested-by
	Reviewed-by
	Signed-off-by
	Suggested-by
	Tested-by
);
my $trailer_re = qr/^(?:@{[ join('|', @TRAILERS) ]}): \S/m;

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

sub _last_block_ok {
	my @lines = @_;
	my $in_annot = 0;

	foreach my $l (@lines) {
		if ($in_annot) {
			$in_annot = 0 if $l =~ /\]\s*$/;
			next;
		}
		next if $l =~ /$trailer_re/;
		if ($l =~ /^\[/) {
			$in_annot = ($l !~ /\]\s*$/);
			next;
		}
		return 0;
	}

	return !$in_annot;
}

sub chk_body_trailers {
	my @paragraphs = split(/\n[ \t]*\n/, $body);

	return unless @paragraphs;
	return unless $body =~ /$trailer_re/m;

	my $last = pop @paragraphs;
	my @last_lines = grep { /\S/ } split(/\n/, $last);
	my $last_ok = @last_lines && _last_block_ok(@last_lines);

	# A trailer-shape line in any earlier paragraph is either a
	# stranded trailer or a blank line inside the trailer block.
	foreach my $p (@paragraphs) {
		foreach my $l (split(/\n/, $p)) {
			if ($l =~ /$trailer_re/) {
				print $E . "Trailers must be a single contiguous block at the end of the message\n";
				return;
			}
		}
	}

	if (!$last_ok) {
		print $E . "Trailer block should contain only trailers or [bracketed annotations]\n";
	}
}

sub chk_body_line_length {
	foreach (split(/\n/, $body)) {
		# Ignore indented lines for command/log output etc and URLs.
		if (/^[ \t]/ || /https?:\/\// || /ftp:\/\//) {
			next;
		}

		# Stop after hitting commit tags/trailers
		if (/$trailer_re/) {
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
