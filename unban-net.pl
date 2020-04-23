#! /usr/bin/perl
use strict;
use warnings;

use constant CHAIN => "blacklist";

my @unused;
open BLACKLIST, '-|', 'iptables -L ' . CHAIN . ' -v -n --line-numbers';
while (<BLACKLIST>) {
	my ($line, $pkt) = /^(\d+)\s+(\d+)/;
	next unless $line;
	next if $pkt;
	push @unused, $line;
}
close BLACKLIST;
foreach my $line (reverse @unused) {
	print 'iptables -D ' . CHAIN . " $line\n";
}
