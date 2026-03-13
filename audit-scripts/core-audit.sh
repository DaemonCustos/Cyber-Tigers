#!/bin/sh
# =====================================================================
#  NCAE CORE AUDIT SCRIPT (UNIVERSAL • POSIX • SAFE • NETWORK-AWARE)
#  Reference Markers: CORE-AUDIT-*
# =====================================================================

# --- Color Flags ------------------------------------------------------
RED="[RED]"
ORANGE="[ORANGE]"
GREEN="[GREEN]"

# --- Initialization ---------------------------------------------------
HOSTNAME="$(hostname 2>/dev/null || echo unknown-host)"
TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown-ts)"
OUTDIR="$HOME/ncae-audits"
OUTFILE="$OUTDIR/${HOSTNAME}-core-audit-$TS.txt"

mkdir -p "$OUTDIR" 2>/dev/null

log() {
    printf "%s\n" "$1" | tee -a "$OUTFILE"
}

log "=== CORE-AUDIT-START ==="
log "Host: $HOSTNAME"
log "Timestamp: $TS"
log ""

# --- Helper: Safe command execution ----------------------------------
runcheck() {
    CMD="$1"
    DESC="$2"
    MARKER="$3"
    REF="$4"

    log "--- $DESC ($MARKER) ---"
    if [ -n "$REF" ]; then
        log "REF: $REF"
    fi

    if command -v ${CMD%% *} >/dev/null 2>&1; then
        sh -c "$CMD" 2>&1 | tee -a "$OUTFILE"
    else
        log "$ORANGE Command not available: $CMD"
    fi
    log ""
}

# =====================================================================
#  SYSTEM IDENTITY
# =====================================================================
runcheck "uname -a" \
    "System identity" \
    "CORE-AUDIT-SYSINFO" \
    "P1-NET-ADDR"

runcheck "cat /etc/os-release" \
    "OS release information" \
    "CORE-AUDIT-OSRELEASE" \
    ""

# =====================================================================
#  TIME SYNCHRONIZATION
# =====================================================================
runcheck "timedatectl status" \
    "Time synchronization state" \
    "CORE-AUDIT-TIME" \
    "P1-NET-ADDR"

runcheck "chronyc tracking" \
    "Chrony tracking (if available)" \
    "CORE-AUDIT-CHRONY" \
    "P1-NET-ADDR"

runcheck "ntpq -p" \
    "NTP peer status (if available)" \
    "CORE-AUDIT-NTP" \
    "P1-NET-ADDR"

# =====================================================================
#  NETWORK INTERFACES
# =====================================================================
runcheck "ip addr show" \
    "Interface bindings (IPv4/IPv6)" \
    "CORE-AUDIT-IFACE" \
    "P1-NET-ADDR"

runcheck "ip link show" \
    "Interface link state" \
    "CORE-AUDIT-LINK" \
    "P1-NET-ADDR"

# =====================================================================
#  ROUTING TABLES
# =====================================================================
runcheck "ip route show" \
    "IPv4 routing table" \
    "CORE-AUDIT-ROUTE4" \
    "P1-NET-ROUTE"

runcheck "ip -6 route show" \
    "IPv6 routing table" \
    "CORE-AUDIT-ROUTE6" \
    "P1-NET-ROUTE"

# =====================================================================
#  LISTENING PORTS
# =====================================================================
runcheck "ss -tulnp" \
    "Listening TCP/UDP ports with processes" \
    "CORE-AUDIT-LISTEN" \
    "P3-FW-LOCK"

# =====================================================================
#  ACTIVE CONNECTIONS
# =====================================================================
runcheck "ss -tunp" \
    "Active TCP/UDP connections" \
    "CORE-AUDIT-CONN" \
    "P3-FW-LOCK"

# =====================================================================
#  FIREWALL ENUMERATION
# =====================================================================
if command -v firewall-cmd >/dev/null 2>&1; then
    runcheck "firewall-cmd --list-all" \
        "FirewallD active zones" \
        "CORE-AUDIT-FW-FIREWALLD" \
        ""
fi

if command -v ufw >/dev/null 2>&1; then
    runcheck "ufw status verbose" \
        "UFW firewall status" \
        "CORE-AUDIT-FW-UFW" \
        ""
fi

if command -v iptables >/dev/null 2>&1; then
    runcheck "iptables -L -n -v" \
        "iptables rules" \
        "CORE-AUDIT-FW-IPTABLES" \
        "P1-FW-BASE"
fi

if command -v nft >/dev/null 2>&1; then
    runcheck "nft list ruleset" \
        "nftables ruleset" \
        "CORE-AUDIT-FW-NFT" \
        "P1-FW-BASE"
fi

# =====================================================================
#  NAT TABLE ENUMERATION
# =====================================================================
if command -v iptables >/dev/null 2>&1; then
    runcheck "iptables -t nat -L -n -v" \
        "NAT table (iptables)" \
        "CORE-AUDIT-NAT-IPTABLES" \
        "P1-FW-BASE"
fi

if command -v nft >/dev/null 2>&1; then
    runcheck "nft list table ip nat" \
        "NAT table (nftables)" \
        "CORE-AUDIT-NAT-NFT" \
        "P1-FW-BASE"
fi

# =====================================================================
#  PACKET FORWARDING STATE
# =====================================================================
runcheck "sysctl net.ipv4.ip_forward" \
    "IPv4 forwarding state" \
    "CORE-AUDIT-FWD4" \
    "P3-KERN-SYSCTL"

runcheck "sysctl net.ipv6.conf.all.forwarding" \
    "IPv6 forwarding state" \
    "CORE-AUDIT-FWD6" \
    "P3-KERN-SYSCTL"

# =====================================================================
#  FILESYSTEM MOUNTS
# =====================================================================
runcheck "mount" \
    "Mounted filesystems" \
    "CORE-AUDIT-MOUNT" \
    "P1-FS-MOUNT"

runcheck "findmnt" \
    "Filesystem mount tree" \
    "CORE-AUDIT-FINDMNT" \
    "P1-FS-MOUNT"

runcheck "cat /etc/fstab" \
    "fstab configuration" \
    "CORE-AUDIT-FSTAB" \
    "P2-FS-FSTABFIX"

# =====================================================================
#  USER & GROUP ENUMERATION
# =====================================================================
runcheck "getent passwd" \
    "User accounts" \
    "CORE-AUDIT-USERS" \
    "P1-USR-ADMIN"

runcheck "getent group" \
    "Group definitions" \
    "CORE-AUDIT-GROUPS" \
    "P2-USR-GROUPFIX"

runcheck "grep -E 'sudo|wheel' /etc/group" \
    "Privileged groups" \
    "CORE-AUDIT-PRIVGROUPS" \
    "P2-USR-GROUPFIX"

# =====================================================================
#  SUDOERS ENUMERATION
# =====================================================================
runcheck "grep -R '' /etc/sudoers /etc/sudoers.d/ 2>/dev/null" \
    "Sudoers configuration" \
    "CORE-AUDIT-SUDOERS" \
    "P3-FS-PERMS"

# =====================================================================
#  CRON / TIMER ENUMERATION
# =====================================================================
runcheck "crontab -l" \
    "User crontab" \
    "CORE-AUDIT-CRONUSER" \
    "P3-CRON-HARDEN"

runcheck "ls -R /etc/cron*" \
    "System cron directories" \
    "CORE-AUDIT-CRONSYS" \
    "P3-CRON-HARDEN"

runcheck "systemctl list-timers" \
    "Systemd timers" \
    "CORE-AUDIT-TIMERS" \
    "P3-CRON-HARDEN"

# =====================================================================
#  SYSTEMD SOCKETS / MOUNTS
# =====================================================================
runcheck "systemctl list-units --type=socket" \
    "Systemd sockets" \
    "CORE-AUDIT-SOCKETS" \
    ""

runcheck "systemctl list-units --type=mount" \
    "Systemd mounts" \
    "CORE-AUDIT-MOUNTS" \
    ""

# =====================================================================
#  KERNEL MODULES
# =====================================================================
runcheck "lsmod" \
    "Loaded kernel modules" \
    "CORE-AUDIT-KMODS" \
    ""

# =====================================================================
#  ENVIRONMENT VARIABLES
# =====================================================================
runcheck "env" \
    "Environment variables" \
    "CORE-AUDIT-ENV" \
    ""

# =====================================================================
#  SERVICE ENUMERATION
# =====================================================================
runcheck "systemctl list-units --type=service --state=running" \
    "Running services" \
    "CORE-AUDIT-SVC-RUNNING" \
    "P3-SVC-DISABLE"

runcheck "systemctl list-unit-files --type=service" \
    "Installed services" \
    "CORE-AUDIT-SVC-INSTALLED" \
    "P3-SVC-DISABLE"

# =====================================================================
#  DNS / DHCP / WEB / DB DETECTION
# =====================================================================
runcheck "ps -ef | grep -E 'named|bind|unbound' | grep -v grep" \
    "DNS service detection" \
    "CORE-AUDIT-DNS" \
    "P1-DNS-BIND"

runcheck "ps -ef | grep -E 'dhcpd|dnsmasq' | grep -v grep" \
    "DHCP service detection" \
    "CORE-AUDIT-DHCP" \
    "P1-DHCP-ISC"

runcheck "ps -ef | grep -E 'nginx|apache|httpd' | grep -v grep" \
    "Web service detection" \
    "CORE-AUDIT-WEB" \
    "P1-WEB-NGINX"

runcheck "ps -ef | grep -E 'mysql|mariadb|postgres' | grep -v grep" \
    "Database service detection" \
    "CORE-AUDIT-DB" \
    "P1-DB-MARIA"

# =====================================================================
#  DANGEROUS DAEMON SCAN
# =====================================================================
runcheck "ps -ef | grep -E 'telnetd|vsftpd|tftp|rsh|rlogin' | grep -v grep" \
    "Dangerous daemon detection" \
    "CORE-AUDIT-DANGER" \
    "P3-SVC-DISABLE"

# =====================================================================
#  UNEXPECTED / HIGH-RISK PORTS
# =====================================================================
runcheck "ss -tulnp | grep -E ':21|:23|:69|:111|:512|:513|:514'" \
    "Unexpected high-risk ports" \
    "CORE-AUDIT-PORTS" \
    "P3-FW-LOCK"

# =====================================================================
#  THIRD-PARTY SECURITY PRODUCTS
# =====================================================================
runcheck "ps -ef | grep -E 'crowdstrike|falcon|sentinel|sophos|clamd' | grep -v grep" \
    "Security product detection" \
    "CORE-AUDIT-SEC" \
    ""

# =====================================================================
#  LOG CONFIGURATION
# =====================================================================
runcheck "journalctl -n 200" \
    "Recent system logs" \
    "CORE-AUDIT-LOGS" \
    ""

# =====================================================================
#  FINALIZATION
# =====================================================================
log "=== CORE-AUDIT-END ==="

