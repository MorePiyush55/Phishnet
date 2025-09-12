# Firejail security profile for browser sandbox
# Restricts browser access to system resources

# Basic sandbox
seccomp
caps.drop all
nonewprivs
noroot

# Network restrictions
netfilter
protocol unix,inet,inet6

# Filesystem restrictions
private-tmp
private-dev
private-etc fonts,ssl,ca-certificates,mime.types,nsswitch.conf,resolv.conf

# Disable dangerous features
noautopulse
nodvd
nogpg
noprinters
nosound
notv
nou2f

# Memory and process restrictions
rlimit-as 2147483648  # 2GB memory limit
rlimit-cpu 300        # 5 minute CPU limit
rlimit-fsize 1073741824  # 1GB file size limit
rlimit-nofile 1024    # File descriptor limit

# Deny access to sensitive directories
blacklist /boot
blacklist /dev/port
blacklist /etc/passwd
blacklist /etc/shadow
blacklist /etc/ssh
blacklist /home/*/.ssh
blacklist /proc/kallsyms
blacklist /proc/kcore
blacklist /proc/kmem
blacklist /proc/mem
blacklist /root
blacklist /sys/firmware
blacklist /sys/kernel/debug
blacklist /usr/sbin
blacklist /usr/src
blacklist /var/backups
blacklist /var/cache/apt
blacklist /var/lib/dpkg
blacklist /var/log

# Whitelist specific directories for browser operation
whitelist /tmp
whitelist /usr/bin/chromium
whitelist /usr/lib/chromium
whitelist /usr/share/fonts
whitelist /usr/share/ca-certificates
whitelist /etc/ssl/certs

# Set environment
env DISPLAY=:99
env HOME=/tmp/browser-home

# Disable shell access
shell none

# Set hostname
hostname browser-sandbox
