#!/bin/sh

TS="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname)"
OUTDIR="$HOME/ncae-shell"
OUTFILE="$OUTDIR/${HOST}-shell-rp-${TS}.txt"

mkdir -p "$OUTDIR"

log() {
    echo "===== $1 =====" >> "$OUTFILE"
}

runcheck() {
    log "$1"
    sh -c "$2" >> "$OUTFILE" 2>&1
    echo "" >> "$OUTFILE"
}

log "SHELL ROLE PACK SCRIPT START"
echo "" >> "$OUTFILE"

# ---------------------------------------------------------
# SERVICE DETECTION — SSH / FTP
# ---------------------------------------------------------

runcheck "SSH Service Status" "systemctl status ssh || systemctl status sshd"
runcheck "FTP Service Status (vsftpd)" "systemctl status vsftpd"
runcheck "FTP Service Status (proftpd)" "systemctl status proftpd"
runcheck "FTP Service Status (pure-ftpd)" "systemctl status pure-ftpd"

# ---------------------------------------------------------
# PORT VISIBILITY
# ---------------------------------------------------------

runcheck "Port Visibility — SSH" "ss -tulnp | grep ':22'"
runcheck "Port Visibility — FTP" "ss -tulnp | grep -E ':21|:20'"

# ---------------------------------------------------------
# SHELL ENUMERATION
# ---------------------------------------------------------

runcheck "List Valid Shells" "cat /etc/shells"
runcheck "User Shell Assignments" "awk -F: '{print \$1, \$7}' /etc/passwd"

# ---------------------------------------------------------
# DANGEROUS SHELL DETECTION
# ---------------------------------------------------------

runcheck "Detect Python Shell Abuse" "grep -R '/usr/bin/python' /etc/passwd"
runcheck "Detect Netcat Shell Abuse" "grep -R 'nc ' /etc/passwd"
runcheck "Detect Bash Assigned to Service Accounts (UID < 1000)" "awk -F: '\$3 < 1000 && \$7 ~ /bash/ {print}' /etc/passwd"

# ---------------------------------------------------------
# AUTHORIZED KEYS VISIBILITY
# ---------------------------------------------------------

runcheck "Authorized Keys — System" "find /root /home -maxdepth 3 -name authorized_keys -exec ls -l {} \;"
runcheck "Authorized Keys Contents" "find /root /home -maxdepth 3 -name authorized_keys -exec cat {} \;"

# ---------------------------------------------------------
# FTP CONFIG VISIBILITY
# ---------------------------------------------------------

runcheck "vsftpd Config" "cat /etc/vsftpd.conf 2>/dev/null"
runcheck "proftpd Config" "cat /etc/proftpd/proftpd.conf 2>/dev/null"
runcheck "pure-ftpd Config Tree" "ls -R /etc/pure-ftpd 2>/dev/null"

# ---------------------------------------------------------
# FTP DIRECTORY PERMISSIONS
# ---------------------------------------------------------

runcheck "FTP Root Permissions (/srv/ftp)" "ls -ld /srv/ftp 2>/dev/null"
runcheck "FTP Upload Directory Permissions (/var/ftp)" "ls -ld /var/ftp 2>/dev/null"

# ---------------------------------------------------------
# SSH CONFIG VISIBILITY
# ---------------------------------------------------------

runcheck "sshd_config" "cat /etc/ssh/sshd_config 2>/dev/null"
runcheck "SSH Host Keys" "ls -l /etc/ssh/ssh_host_*"
runcheck "SSH AuthorizedKeysFile Directives" "grep -R 'AuthorizedKeysFile' /etc/ssh/sshd_config 2>/dev/null"
runcheck "All authorized_keys Files on System" "find / -name authorized_keys 2>/dev/null -exec ls -l {} \;"

# ---------------------------------------------------------
# LOGGING VISIBILITY
# ---------------------------------------------------------

runcheck "SSH Logs" "journalctl -u ssh -n 200 || journalctl -u sshd -n 200"
runcheck "FTP Logs" "journalctl -u vsftpd -n 200 || journalctl -u proftpd -n 200 || journalctl -u pure-ftpd -n 200"

# ---------------------------------------------------------
# FIREWALL VISIBILITY
# ---------------------------------------------------------

runcheck "Firewall Rules (iptables)" "iptables -L -n -v"
runcheck "Firewall Rules (nft)" "nft list ruleset"

# ---------------------------------------------------------
# SUSPICIOUS PROCESS & BINARY VISIBILITY
# ---------------------------------------------------------

runcheck "All Processes (PID, User, Command)" "ps -eo pid,user,cmd --sort=pid"
runcheck "Processes with Deleted Executables" "ls -l /proc/*/exe 2>/dev/null | grep deleted || true"
runcheck "Process Working Directories" "find /proc/*/cwd -maxdepth 0 -exec ls -l {} \; 2>/dev/null"
runcheck "Process Executable Paths" "find /proc/*/exe -maxdepth 0 -exec readlink {} \; 2>/dev/null"

# ---------------------------------------------------------
# SUSPICIOUS NETWORK CONNECTIONS
# ---------------------------------------------------------

runcheck "All Listening Sockets" "ss -tulnp"
runcheck "Established TCP Connections" "ss -tanp | grep ESTAB || true"
runcheck "Open Network Files (lsof)" "lsof -i -n -P 2>/dev/null"

# ---------------------------------------------------------
# CRON / SYSTEMD PERSISTENCE
# ---------------------------------------------------------

runcheck "User Crontab (root)" "crontab -l 2>/dev/null || echo 'no crontab for root'"
runcheck "System Cron Directories" "ls -R /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null"
runcheck "Systemd Timers" "systemctl list-timers --all"
runcheck "Enabled Systemd Services" "systemctl list-unit-files | grep enabled"

# ---------------------------------------------------------
# HIDDEN USERS / UID ANOMALIES
# ---------------------------------------------------------

runcheck "UID 0 Accounts" "awk -F: '\$3 == 0 {print}' /etc/passwd"
runcheck "System Accounts (UID < 1000)" "awk -F: '\$3 < 1000 {print}' /etc/passwd"

# ---------------------------------------------------------
# SUID / SGID BINARIES
# ---------------------------------------------------------

runcheck "SUID Binaries" "find / -perm -4000 -type f 2>/dev/null"
runcheck "SGID Binaries" "find / -perm -2000 -type f 2>/dev/null"

# ---------------------------------------------------------
# ENVIRONMENT VARIABLE ABUSE
# ---------------------------------------------------------

runcheck "Environment Variables" "env"
runcheck "LD_PRELOAD References in /etc" "grep -R 'LD_PRELOAD' /etc 2>/dev/null || true"
runcheck "PATH Settings in Global Profiles" "grep -R 'PATH=' /etc/profile /etc/bash* 2>/dev/null || true"

# ---------------------------------------------------------
# TEMPORARY DIRECTORY ABUSE
# ---------------------------------------------------------

runcheck "Contents of /tmp" "ls -R /tmp 2>/dev/null"
runcheck "Contents of /var/tmp" "ls -R /var/tmp 2>/dev/null"
runcheck "Contents of /dev/shm" "ls -R /dev/shm 2>/dev/null"

# ---------------------------------------------------------
# KERNEL MODULE VISIBILITY
# ---------------------------------------------------------

runcheck "Loaded Kernel Modules" "lsmod"
runcheck "Kernel Module Messages" "dmesg | grep -i module || true"

# ---------------------------------------------------------
# UNEXPECTED SERVICES / SYSTEMD UNITS
# ---------------------------------------------------------

runcheck "All Active Services" "systemctl list-units --type=service"
runcheck "All Enabled Unit Files" "systemctl list-unit-files | grep enabled"

# ---------------------------------------------------------
# SAFE SERVICE ENABLEMENT
# ---------------------------------------------------------

runcheck "Enable SSH" "systemctl enable ssh || systemctl enable sshd"
runcheck "Start SSH" "systemctl start ssh || systemctl start sshd"
runcheck "Enable vsftpd (if present)" "systemctl enable vsftpd || true"
runcheck "Start vsftpd (if present)" "systemctl start vsftpd || true"

log "SHELL ROLE PACK SCRIPT COMPLETE"
echo "" >> "$OUTFILE"
