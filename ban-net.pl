#! /usr/bin/perl -s
use strict;
use warnings;
use feature qw(switch);
use DateTime::Format::Strptime;
use Data::Dumper;
use Net::Netmask;
no if $] >= 5.018, warnings => "experimental::smartmatch";

use constant AUTH_LOG_1 => "/var/log/auth.log.1";
use constant AUTH_LOG => "/var/log/auth.log";
use constant MAIL_LOG_1 => "/var/log/mail.log.1";
use constant MAIL_LOG => "/var/log/mail.log";
use constant PAM_GENERIC_CONF => "/etc/fail2ban/filter.d/pam-generic.conf";
use constant SSH_CONF => "/etc/fail2ban/filter.d/sshd.conf";
use constant SSH_DDOS_CONF => "/etc/fail2ban/filter.d/sshd-ddos.conf";
use constant SENDMAIL_CONF => "/etc/fail2ban/filter.d/exim.conf";
use constant DOVECOT_CONF => "/etc/fail2ban/filter.d/dovecot.conf";
use constant DOVECOT_POP3IMAP_CONF =>
	"/etc/fail2ban/filter.d/dovecot-pop3imap.conf";
use constant MIN_FAIL_NET => 5;
use constant MIN_FAIL_HOST => 20;
use constant MIN_FAIL_SUBNET => 2;
use constant MIN_FAIL_SUBCOUNT => 40;
use constant CHAIN => "blacklist";

my @conf = ([AUTH_LOG_1, SSH_CONF],
			[AUTH_LOG, SSH_CONF],
			[AUTH_LOG_1, SSH_DDOS_CONF],
			[AUTH_LOG, SSH_DDOS_CONF],
			[AUTH_LOG_1, PAM_GENERIC_CONF],
			[AUTH_LOG, PAM_GENERIC_CONF],
			[MAIL_LOG_1, SENDMAIL_CONF],
			[MAIL_LOG, SENDMAIL_CONF],
			[MAIL_LOG_1, DOVECOT_POP3IMAP_CONF],
			[MAIL_LOG, DOVECOT_POP3IMAP_CONF],
);

my @whitelist = qw(192.168.176/23 192.168.178/24);
 
foreach my $net (@whitelist) {
	my $block = new Net::Netmask($net);
	$block->storeNetblock();
}

our $from;
our $interval;
our $list;

my $parser = DateTime::Format::Strptime->new(pattern => '%a %b %d %T %Y');
my $from_dt;
if ($from) {
	$from_dt = $parser->parse_datetime($from);
} elsif ($interval) {
	my %duration;
	my @interval = split(/\s+/, $interval);
	while (my ($count, $unit) = splice @interval, 0, 2) {
		$duration{$unit} = $count if $unit;
	}
	$from_dt = DateTime->now - DateTime::Duration->new(%duration);
} else {
	$from_dt = DateTime->from_epoch(epoch => 0);
}

my %hosts;
open BLACKLIST, '-|', 'iptables -L ' . CHAIN . ' -n --line-numbers' or die;
while (<BLACKLIST>) {
	next unless /^\d+\s+DROP/;
	chomp;
	my ($line, $target, $proto, $opt, $source, $dest) = split /\s+/;
	my ($a0, $a1, $a2, $a3, $len) =
		$source =~ m{^(\d+)\.(\d+)\.(\d+)\.(\d+)/?(\d*)};
	$len ||= 32;
	#print "from blacklist: $_\n";
	given ($len) {
		when (8)  {
			$hosts{$a0} =
				{count => MIN_FAIL_SUBNET, line => $line, lvl => 1, ipt => 1};
		}
		when (16) {
			$hosts{$a0}{next}{$a1} =
				{count => MIN_FAIL_SUBNET, line => $line, lvl => 2, ipt => 1};
		}
		when (24) {
			$hosts{$a0}{next}{$a1}{next}{$a2} =
				{count => MIN_FAIL_SUBNET, line => $line, lvl => 3, ipt => 1};
		}
		when (32) {
			$hosts{$a0}{next}{$a1}{next}{$a2}{next}{$a3} =
				{count => MIN_FAIL_HOST, line => $line, lvl => 4, ipt => 1};
		}
	}
}
close BLACKLIST;
#print Dumper(\%hosts);

foreach my $conf (@conf) {
	my ($log, $conf) = @$conf;
	next unless -r $conf && -r $log;
	open FAIL2BAN, '-|', sprintf 'fail2ban-regex -v %s %s', $log, $conf or die;
	while (<FAIL2BAN>) {
		chomp;
		#my ($a0, $a1, $a2, $a3, $ts) = /^\|\s+(\d+)\.(\d+)\.(\d+)\.(\d+)\s+\(([^)]+)\)/;
		my ($a0, $a1, $a2, $a3, $ts) = /^\|\s+(\d+)\.(\d+)\.(\d+)\.(\d+)\s+(.*)/;
		next unless $ts;
		next if findNetblock("$a0.$a1.$a2.$a3");
		next if $a0 eq 127;
		my $dt = $parser->parse_datetime($ts);
		next if DateTime->compare($from_dt, $dt) == 1;
		$hosts{$a0}{next}{$a1}{next}{$a2}{next}{$a3}{count}++;
		$hosts{$a0}{next}{$a1}{next}{$a2}{next}{$a3}{lvl} = 4;
	}
	close FAIL2BAN;
}
#print Dumper(\%hosts);
sub aggregate;
sub aggregate {
	my ($parent, $node) = @_;
	aggregate $node, $_ foreach (values %{$node->{next}});
	if (($node->{lvl}//0) == 4) {
		$node->{ban} = 1 if $node->{count} >= MIN_FAIL_HOST;
		$parent->{count}++ if $parent && $node->{count} >= MIN_FAIL_NET;
	} else {
		$node->{ban} = 1 if ($node->{count}//0) >= MIN_FAIL_SUBNET;
		$node->{ban} = 1 if ($node->{subfail}//0) >= MIN_FAIL_SUBCOUNT;
		$parent->{count}++ if $node->{ban};
		$parent->{subfail}++;
	}
	$parent->{line} = $node->{line} if $parent && $node->{line} &&
		$node->{line} < ($parent->{line}//10000000);
}
aggregate(undef, $hosts{$_}) foreach (keys %hosts);
#print Dumper(\%hosts);
sub makenet {
	my ($prefix, $addr, $lvl) = @_;
	$prefix .= '.' if $prefix;
	return "$prefix$addr" if $lvl == 3;
	my $suffix;
	$suffix .= '.0' x (3 - $lvl);
	my $length = '/' . (8 * ($lvl + 1));
	return "$prefix$addr$suffix$length";
}

sub logaddr {
	my ($net, $ipt, $line, $ban, $count, $subfail) = @_;
	return unless $list;

	$count //= 0;
	my $flag = $ipt ? 't' : '';	# table: aready banned
	$flag = 'p' if $line && ! $ipt;	# parent: subnet/host already banned
	$flag = 'b' if $ban && ! $ipt;	# ban: to be banned
	printf "%-18s %1s %3d",
		$net, $flag, $count if $count || $subfail;
	printf " %3d", $subfail if $subfail;
	print "\n" if $count || $subfail;
}

sub ban;
sub ban {
	my ($lvl, $prefix, $addr, $node) = @_;
	my $net = makenet $prefix, $addr, $lvl;
	#print "ban called: $lvl '$prefix' '$addr' '$net'\n";
	logaddr($net, $node->{ipt}, $node->{line}, $node->{ban}, $node->{count},
		$node->{subfail});
	if ($node->{ban}) {
		if (!$list) {
			if ($node->{line}) {
				if ($node->{ipt}) {
					print "# keep $net line $node->{line}\n";
				} else {
					printf "iptables -R %s %d -s '%s' -j DROP\n",
						CHAIN, $node->{line}, $net;
				}
			} else {
				printf "iptables -A %s -s '%s' -j DROP\n", CHAIN, $net;
			}
		}
	} else {
		my $nextaddr = $prefix ? "$prefix.$addr" : $addr;
		ban($lvl + 1, $nextaddr, $_, $node->{next}{$_})
			foreach (sort {$a <=> $b} keys %{$node->{next}});
	}
}

ban(0, '', $_, $hosts{$_}) foreach (sort {$a <=> $b} keys %hosts);

__END__

Copyright (c) 2017-2020, Jörg Sommrey. All rights reserved.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See L<http://dev.perl.org/licenses/> for more information.

