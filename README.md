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
iptables -I INPUT -p tcp -m multiport --dports 20,21,22,25,110,143,465,587,998,990,993,995 -m state --state NEW -j blacklist
```
Run the scripts `ban-net.pl` and `unban-net.pl` on a regular schedule, e.g. by cron:

```
PATH=/usr/local/bin:/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin
# min   hour    dom     month   dow     user    command
13      19      *       *       *       root    unban-net.pl | sh; iptables -Z blacklist
14      1-19/6  *       *       *       root    ban-net.pl -interval="2 days"| sh
```
Adjust values to your needs.