# AppArmor profile for secure browser execution
# This profile restricts browser capabilities for security

#include <tunables/global>

/usr/bin/chromium flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/fonts>
  #include <abstractions/X>
  #include <abstractions/audio>
  #include <abstractions/dri>
  #include <abstractions/mesa>
  
  # Allow reading system libraries
  /lib{,32,64}/** mr,
  /usr/lib{,32,64}/** mr,
  /usr/share/** r,
  
  # Allow temporary files
  /tmp/** rw,
  /var/tmp/** rw,
  
  # Allow browser binary
  /usr/bin/chromium rix,
  /usr/lib/chromium/** rix,
  
  # Network access (restricted)
  network inet stream,
  network inet6 stream,
  
  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability dac_override,
  
  # Deny access to sensitive files
  deny /etc/passwd r,
  deny /etc/shadow r,
  deny /proc/*/mem r,
  deny /sys/kernel/debug/** r,
  
  # Allow reading configuration
  /etc/fonts/** r,
  /etc/ssl/certs/** r,
  
  # Browser cache and data
  owner /tmp/chromium-cache/** rw,
  owner /tmp/playwright-*/** rw,
  
  # Allow required devices
  /dev/null rw,
  /dev/zero r,
  /dev/random r,
  /dev/urandom r,
  
  # X11 socket
  /tmp/.X11-unix/* rw,
  
  # Deny process tracing
  deny ptrace,
  
  # Memory protections
  deny @{PROC}/sys/kernel/core_pattern w,
  deny @{PROC}/sys/fs/suid_dumpable w,
}
