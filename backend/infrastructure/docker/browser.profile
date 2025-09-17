# Firejail profile for PhishNet browser isolation
noblacklist /app
noblacklist /opt/ms-playwright

# Filesystem restrictions
blacklist /boot
blacklist /etc/shadow
blacklist /etc/passwd
blacklist /etc/group
blacklist /root
blacklist /home
blacklist /var/log
blacklist /sys
blacklist /proc/sys

# Private directories
private-tmp
private-dev
private-etc passwd,group,hostname,hosts,nsswitch.conf,resolv.conf,localtime
private-bin python3,python,sh,bash

# Network restrictions
netfilter
net none  # Will be overridden by docker network

# Security options
caps.drop all
nonewprivs
noroot
seccomp
protocol unix,inet,inet6

# Resource limits
rlimit-cpu 120
rlimit-nofile 1024
rlimit-nproc 20
rlimit-data 1048576000  # 1GB
rlimit-rss 536870912   # 512MB

# AppArmor
apparmor

# Read-only filesystem with exceptions
read-only /
read-write /app/screenshots
read-write /app/logs
read-write /app/temp
read-write /tmp
