#!/bin/sh

# ================================================================
#  LNX ROLE PACK — INITIALIZATION (WITH SEVERITY)
# ================================================================
HOSTNAME=$(hostname 2>/dev/null || echo "unknown-host")
TS=$(date +"%Y%m%d-%H%M%S")
OUTDIR="$HOME/ncae-audits"
OUTFILE="$OUTDIR/${HOSTNAME}-lnx-rp-${TS}.txt"

mkdir -p "$OUTDIR"

log() {
    printf "%s\n" "$1" | tee -a "$OUTFILE"
}

runcheck() {
    CMD="$1"
    DESC="$2"
    REF="$3"
    SEV="$4"

    log ""
    log "=== $DESC ==="
    log "REF: $REF"
    log "SEVERITY: $SEV"
    log "CMD: $CMD"
    log "--- OUTPUT START ---"
    sh -c "$CMD" 2>&1 | tee -a "$OUTFILE"
    log "--- OUTPUT END ---"
}

log "=== LNX ROLE PACK START (WITH SEVERITY) ==="
log "Hostname: $HOSTNAME"
log "Timestamp: $TS"
log "Output File: $OUTFILE"

# ================================================================
#  SYSTEM IDENTIFICATION — P1-LN-SYS
# ================================================================
runcheck "uname -a" \
    "Basic system info" \
    "P1-LN-SYS" \
    "GREEN"

runcheck "cat /etc/os-release 2>/dev/null || cat /etc/*release 2>/dev/null" \
    "OS release information" \
    "P1-LN-SYS" \
    "GREEN"

runcheck "hostname; hostname -f 2>/dev/null || true" \
    "Hostname and FQDN" \
    "P1-LN-SYS" \
    "GREEN"

runcheck "date; timedatectl 2>/dev/null || true" \
    "Time and timezone" \
    "P1-LN-SYS" \
    "ORANGE"

runcheck "cat /etc/resolv.conf 2>/dev/null || true" \
    "DNS resolver configuration" \
    "P1-LN-SYS" \
    "ORANGE"

# ================================================================
#  SERVICE ENUMERATION — P1-LN-SVC
# ================================================================
runcheck "systemctl list-unit-files --type=service 2>/dev/null || true" \
    "Systemd services (enabled + disabled)" \
    "P1-LN-SVC" \
    "ORANGE"

runcheck "systemctl list-units --type=service --all 2>/dev/null || true" \
    "Systemd services (active)" \
    "P1-LN-SVC" \
    "ORANGE"

runcheck "ls -l /etc/init.d 2>/dev/null || true" \
    "Init scripts (SysV)" \
    "P1-LN-SVC" \
    "ORANGE"

# ================================================================
#  TIMERS AND SCHEDULING — P1-LN-TIMER
# ================================================================
runcheck "systemctl list-timers --all 2>/dev/null || true" \
    "Systemd timers" \
    "P1-LN-TIMER" \
    "ORANGE"

runcheck "ls -l /etc/cron* 2>/dev/null || true" \
    "Cron directories" \
    "P1-LN-TIMER" \
    "ORANGE"

runcheck "cat /etc/crontab 2>/dev/null || true" \
    "System-wide crontab" \
    "P1-LN-TIMER" \
    "ORANGE"

runcheck "ls -l /var/spool/cron /var/spool/cron/crontabs 2>/dev/null || true" \
    "User crontabs" \
    "P1-LN-TIMER" \
    "ORANGE"

# ================================================================
#  USERS AND GROUPS — P1-LN-USERS
# ================================================================
runcheck "cat /etc/passwd 2>/dev/null || true" \
    "Local users" \
    "P1-LN-USERS" \
    "ORANGE"

runcheck "cat /etc/group 2>/dev/null || true" \
    "Local groups" \
    "P1-LN-USERS" \
    "ORANGE"

runcheck "cat /etc/sudoers 2>/dev/null; ls -l /etc/sudoers.d 2>/dev/null || true" \
    "Sudoers configuration" \
    "P1-LN-USERS" \
    "RED"

# ================================================================
#  SUID/SGID BINARIES — P1-LN-SUID
# ================================================================
runcheck "find / -xdev -type f -perm -4000 -printf \"%p %u %g %m\n\" 2>/dev/null || true" \
    "SUID binaries" \
    "P1-LN-SUID" \
    "RED"

runcheck "find / -xdev -type f -perm -2000 -printf \"%p %u %g %m\n\" 2>/dev/null || true" \
    "SGID binaries" \
    "P1-LN-SUID" \
    "RED"

# ================================================================
#  WORLD-WRITABLE PATHS — P1-LN-WW
# ================================================================
runcheck "find / -xdev -type d -perm -0002 ! -perm -1000 -printf \"%p %m\n\" 2>/dev/null || true" \
    "World-writable directories (no sticky bit)" \
    "P1-LN-WW" \
    "RED"

runcheck "find / -xdev -type f -perm -0002 -printf \"%p %m\n\" 2>/dev/null || true" \
    "World-writable files" \
    "P1-LN-WW" \
    "RED"

# ================================================================
#  SSH CONFIGURATION — P1-LN-SSH
# ================================================================
runcheck "grep -v '^[[:space:]]*#' /etc/ssh/sshd_config 2>/dev/null || true" \
    "SSH daemon configuration" \
    "P1-LN-SSH" \
    "RED"

runcheck "find /root -maxdepth 3 -name \"authorized_keys\" -print -exec cat {} \\; 2>/dev/null || true" \
    "SSH authorized_keys (root)" \
    "P1-LN-SSH" \
    "RED"

runcheck "find /home -maxdepth 5 -name \"authorized_keys\" -print -exec cat {} \\; 2>/dev/null || true" \
    "SSH authorized_keys (users)" \
    "P1-LN-SSH" \
    "RED"

# ================================================================
#  PATH AND SHELL PROFILES — P1-LN-PATH
# ================================================================
runcheck "ls -l /etc/profile /etc/bash.bashrc /etc/zsh/zshrc 2>/dev/null || true" \
    "Global shell profiles" \
    "P1-LN-PATH" \
    "ORANGE"

runcheck "find /root /home -maxdepth 3 -name \".bashrc\" -o -name \".profile\" -o -name \".bash_profile\" 2>/dev/null || true" \
    "User shell profiles" \
    "P1-LN-PATH" \
    "ORANGE"

runcheck "echo \"PATH=$PATH\"" \
    "Current PATH" \
    "P1-LN-PATH" \
    "GREEN"

runcheck "echo \"$PATH\" | tr ':' '\n' | sed 's/^/PATH_ENTRY: /'" \
    "Suspicious PATH entries" \
    "P1-LN-PATH" \
    "ORANGE"

# ================================================================
#  KERNEL MODULES — P1-LN-KMOD
# ================================================================
runcheck "lsmod 2>/dev/null || true" \
    "Loaded kernel modules" \
    "P1-LN-KMOD" \
    "ORANGE"

runcheck "grep -R \"^blacklist\" /etc/modprobe.d 2>/dev/null || true" \
    "Module blacklist configuration" \
    "P1-LN-KMOD" \
    "GREEN"

# ================================================================
#  PACKAGE MANAGER INTEGRITY — P1-LN-PKG
# ================================================================
runcheck "if command -v apt >/dev/null 2>&1; then ls -l /etc/apt/sources.list*; apt-cache policy 2>/dev/null; fi" \
    "APT sources and status" \
    "P1-LN-PKG" \
    "ORANGE"

runcheck "if command -v yum >/dev/null 2>&1; then yum repolist all 2>/dev/null; fi; if command -v dnf >/dev/null 2>&1; then dnf repolist all 2>/dev/null; fi" \
    "YUM/DNF repos and status" \
    "P1-LN-PKG" \
    "ORANGE"

runcheck "if command -v rpm >/dev/null 2>&1; then rpm -Va 2>/dev/null | head -n 200; fi" \
    "Package verification (RPM)" \
    "P1-LN-PKG" \
    "RED"

runcheck "if command -v dpkg >/dev/null 2>&1; then dpkg -V 2>/dev/null | head -n 200; fi" \
    "Package verification (dpkg)" \
    "P1-LN-PKG" \
    "RED"

# ================================================================
#  PROCESS AND LISTENER ENUMERATION — P1-LN-PS
# ================================================================
runcheck "ps auxww 2>/dev/null || ps -ef 2>/dev/null || true" \
    "Process list (full)" \
    "P1-LN-PS" \
    "ORANGE"

runcheck "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || true" \
    "Network listeners" \
    "P1-LN-PS" \
    "RED"

runcheck "ps auxww --sort=-%cpu 2>/dev/null | head -n 25 || true" \
    "Top CPU processes" \
    "P1-LN-PS" \
    "ORANGE"

runcheck "ps auxww --sort=-%mem 2>/dev/null | head -n 25 || true" \
    "Top memory processes" \
    "P1-LN-PS" \
    "ORANGE"

# ================================================================
#  PERSISTENCE MECHANISMS — P1-LN-PERSIST
# ================================================================
runcheck "ls -l /etc/rc.local /etc/rc.d/rc.local 2>/dev/null; grep -v '^[[:space:]]*#' /etc/rc.local 2>/dev/null || true" \
    "rc.local and legacy startup scripts" \
    "P1-LN-PERSIST" \
    "RED"

runcheck "grep -R \"nc \" /etc/profile /etc/bash.bashrc /etc/zsh/zshrc 2>/dev/null || true" \
    "Profile-based persistence (global)" \
    "P1-LN-PERSIST" \
    "RED"

runcheck "grep -R \"nc \" /root /home 2>/dev/null || true" \
    "Profile-based persistence (user)" \
    "P1-LN-PERSIST" \
    "RED"

# ================================================================
#  ROGUE BINARIES AND INTERPRETERS — P1-LN-ROGUE
# ================================================================
runcheck "command -v nc 2>/dev/null; command -v ncat 2>/dev/null; command -v socat 2>/dev/null || true" \
    "Common attacker tools (nc, ncat, socat)" \
    "P1-LN-ROGUE" \
    "RED"

runcheck "command -v python 2>/dev/null; command -v python3 2>/dev/null; command -v perl 2>/dev/null; command -v ruby 2>/dev/null || true" \
    "Python, Perl, Ruby interpreters" \
    "P1-LN-ROGUE" \
    "ORANGE"

runcheck "find /tmp /dev/shm -maxdepth 4 -type f -perm -111 -printf \"%p %m\n\" 2>/dev/null || true" \
    "Suspicious binaries in /tmp and /dev/shm" \
    "P1-LN-ROGUE" \
    "RED"

# ================================================================
#  LOGS AND ANOMALIES — P1-LN-LOGS
# ================================================================
runcheck "journalctl -n 500 2>/dev/null || true" \
    "System logs (journalctl tail)" \
    "P1-LN-LOGS" \
    "ORANGE"

runcheck "grep -i \"fail\" /var/log/auth.log 2>/dev/null | tail -n 100 || grep -i \"fail\" /var/log/secure 2>/dev/null | tail -n 100 || true" \
    "Authentication failures" \
    "P1-LN-LOGS" \
    "RED"

runcheck "last -n 50 2>/dev/null || true" \
    "Last logins" \
    "P1-LN-LOGS" \
    "ORANGE"

# ================================================================
#  FILESYSTEM INTEGRITY — P1-LN-FS
# ================================================================
runcheck "mount || true" \
    "Mounted filesystems" \
    "P1-LN-FS" \
    "GREEN"

runcheck "df -h 2>/dev/null || true" \
    "Disk usage" \
    "P1-LN-FS" \
    "GREEN"

runcheck "find /etc /var /usr /opt -maxdepth 3 -name \".*\" -type f 2>/dev/null || true" \
    "Hidden files in critical directories" \
    "P1-LN-FS" \
    "ORANGE"

# ================================================================
#  ENVIRONMENT VARIABLES — P1-LN-ENV
# ================================================================
runcheck "env 2>/dev/null || true" \
    "Environment variables (root shell)" \
    "P1-LN-ENV" \
    "ORANGE"

runcheck "env | grep -E '^LD_' 2>/dev/null || true" \
    "Suspicious LD_* variables" \
    "P1-LN-ENV" \
    "RED"

# ================================================================
#  SYSTEM EXPOSURE SNAPSHOT — P1-LN-EXPOSE
# ================================================================
runcheck "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || true" \
    "Listening services summary" \
    "P1-LN-EXPOSE" \
    "RED"

runcheck "iptables -L -n 2>/dev/null || nft list ruleset 2>/dev/null || true" \
    "Firewall state snapshot" \
    "P1-LN-EXPOSE" \
    "ORANGE"

# ================================================================
#  FINALIZATION
# ================================================================
log "=== LNX ROLE PACK END (WITH SEVERITY) ==="
