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

__END__

Copyright (c) 2017-2020, Jörg Sommrey. All rights reserved.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See L<http://dev.perl.org/licenses/> for more information.
