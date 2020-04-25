# ban-net - fail2ban based blacklisting of hosts and subnets
## Description
Logfiles are analyzed using existing fail2ban configuration.
Regardless of actions taken by fail2ban, these scripts perform a blacklisting in an additional layer.
IP ranges in this blacklist can be partly or completely locked out.
When there is no traffic from the blocked addresses for some time, the blacklisting will be undone.
## Usage
A working fail2ban configuration is required for these scripts.
First, pairs of logfiles and fail2ban configuration files must be configured in the array `@conf` in `ban-net.pl`.
(There is a `@whitelist` that may be configured, too.)

Install the scripts `ban-net.pl` and `unban-net.pl` in an appropiate directory, e.g. `/usr/local/sbin`.

Create a new chain "blacklist" in iptables:
```
iptables -N blacklist
```
Jump to this chain from the INPUT chain, unconditional or for specific ports.
(The latter has the advantage that these adresses remain accessible.)
```
iptables -I INPUT -p tcp -m multiport --dports ftp-data,ftp,ssh,smtp,pop3,imap2,urd,submission,ftps,imaps,pop3s -m state --state NEW -j blacklist
```
Run the scripts `ban-net.pl` and `unban-net.pl` on a regular schedule, e.g. by cron:

```
PATH=/usr/local/bin:/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin
# min   hour    dom     month   dow     user    command
13      19      *       *       *       root    unban-net.pl | sh; iptables -Z blacklist
14      1-19/6  *       *       *       root    ban-net.pl -interval="2 days"| sh
```
Adjust values to your needs.
### ban-net.pl
This program performes the configured log file analysis and counts access
violations per IP address.
It does not modify entries in the blacklist chain but instead generates
statements that need to be fed into a shell to do so.

The program has three options:

- __-from=__*datetime*

    process log entries from the given time onwards.
    
- __-interval=__*interval*

    process log entries from the given relative time interval
    
- __-list__

    causes the program not to generate iptables statements.
    Instead it gives a report about the current state and the actions that
    woud be generated if called without __-list__
    
    It reports the address or subnet, a flag, the number of reported violations and
    the number of reported subitems, if any.
    
    Flag is __t__ for an entry already present in the blacklist chain, __b__ for
    an entry that would be generated and __p__ for an entry that has blacklisted
    subentries.

### unban-net.pl
This program generates iptables commands to delete entries from the blacklist
chain that have a packet counter of zero.
A call to `iptables -Z blacklist` is required after `unban-net.pl` has been run.
