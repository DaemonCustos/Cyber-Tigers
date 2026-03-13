#!/bin/sh
# =====================================================================
#  NCAE DNS ROLE PACK SCRIPT (UNIVERSAL • POSIX • AUTO-DETECT)
#  Supports: Bind9 • Unbound • dnsmasq
# =====================================================================

# --- Global Variables -------------------------------------------------
HOSTNAME="$(hostname 2>/dev/null || echo unknown-host)"
TS="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown-ts)"
USER="$(whoami 2>/dev/null || echo unknown)"
HOME="${HOME:-/home/$USER}"
SHELL="$(basename "$SHELL" 2>/dev/null || echo sh)"
OS="$(uname -s 2>/dev/null || echo unknown)"
KERNEL="$(uname -r 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
DISTRO="$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"

OUTDIR="$HOME/ncae-dns"
LOGDIR="$OUTDIR/logs"
TMPDIR="$OUTDIR/tmp"
OUTFILE="$OUTDIR/${HOSTNAME}-dns-rp-$TS.txt"

mkdir -p "$OUTDIR" "$LOGDIR" "$TMPDIR" 2>/dev/null

# --- Logging ----------------------------------------------------------
log() {
    printf "%s\n" "$1" | tee -a "$OUTFILE"
}

log "=== DNS-RP-START ==="
log "Host: $HOSTNAME"
log "Timestamp: $TS"
log "OS: $OS | Distro: $DISTRO | Kernel: $KERNEL | Arch: $ARCH"
log ""

# --- Helper: Safe Command Execution ----------------------------------
runcheck() {
    CMD="$1"
    DESC="$2"
    REF="$3"

    log "--- $DESC ($REF) ---"
    if command -v ${CMD%% *} >/dev/null 2>&1; then
        sh -c "$CMD" 2>&1 | tee -a "$OUTFILE"
    else
        log "[ORANGE] Command not available: $CMD"
    fi
    log ""
}

# =====================================================================
#  SERVICE AUTO-DETECTION
# =====================================================================
log "--- DNS Service Auto-Detection (P1-DNS-DETECT) ---"

HAS_BIND=0
HAS_UNBOUND=0
HAS_DNSMASQ=0
HAS_DNS=0
DNS_SERVICE="none"

if systemctl is-active --quiet bind9 2>/dev/null || systemctl is-active --quiet named 2>/dev/null; then
    HAS_BIND=1
    HAS_DNS=1
    DNS_SERVICE="bind"
    log "Detected: BIND9/NAMED"
fi

if systemctl is-active --quiet unbound 2>/dev/null; then
    HAS_UNBOUND=1
    HAS_DNS=1
    DNS_SERVICE="unbound"
    log "Detected: UNBOUND"
fi

if systemctl is-active --quiet dnsmasq 2>/dev/null; then
    HAS_DNSMASQ=1
    HAS_DNS=1
    DNS_SERVICE="dnsmasq"
    log "Detected: DNSMASQ"
fi

if [ "$HAS_DNS" -eq 0 ]; then
    log "[RED] No active DNS service detected."
fi
log ""

# --- Service-Specific Paths ------------------------------------------
BIND_CONF="/etc/bind"
BIND_MAIN_CONF="/etc/bind/named.conf"
BIND_LOG="/var/log/named"
BIND_VAR="/var/cache/bind"

UNBOUND_CONF="/etc/unbound"
UNBOUND_MAIN_CONF="/etc/unbound/unbound.conf"
UNBOUND_LOG="/var/log/unbound"
UNBOUND_VAR="/var/lib/unbound"

DNSMASQ_CONF="/etc/dnsmasq.conf"
DNSMASQ_D="/etc/dnsmasq.d"
DNSMASQ_LOG="/var/log/dnsmasq.log"
DNSMASQ_VAR="/var/lib/misc"

RESOLV_CONF="/etc/resolv.conf"

# =====================================================================
#  UNIVERSAL ENUMERATION
# =====================================================================
runcheck "ss -tulnp | grep -E ':53 '" \
    "DNS ports (53) listening" \
    "P1-DNS-PORTS"

runcheck "ps -ef | grep -E 'named|bind|unbound|dnsmasq' | grep -v grep" \
    "DNS service processes" \
    "P1-DNS-DETECT"

runcheck "cat $RESOLV_CONF" \
    "System resolver configuration" \
    "P1-DNS-RESOLV"

runcheck "iptables -L -n -v" \
    "Firewall exposure for DNS" \
    "P1-DNS-FW"

# =====================================================================
#  SERVICE ENABLEMENT STATE
# =====================================================================
runcheck "systemctl is-enabled bind9 || systemctl is-enabled named || true" \
    "Bind9 enablement state" \
    "P2-DNS-SVCFIX"

runcheck "systemctl is-enabled unbound || true" \
    "Unbound enablement state" \
    "P2-DNS-SVCFIX"

runcheck "systemctl is-enabled dnsmasq || true" \
    "dnsmasq enablement state" \
    "P2-DNS-SVCFIX"

# =====================================================================
#  BIND9 ENUMERATION
# =====================================================================
if [ "$HAS_BIND" -eq 1 ]; then
    runcheck "systemctl status bind9 || systemctl status named" \
        "Bind9 service status" \
        "P1-DNS-DETECT"

    runcheck "named-checkconf $BIND_MAIN_CONF" \
        "Bind9 configuration check" \
        "P2-DNS-CONFFIX"

    runcheck "ls -R $BIND_CONF" \
        "Bind9 configuration directory" \
        "P1-DNS-CONF"

    runcheck "ls -R $BIND_VAR" \
        "Bind9 zone/cache directory" \
        "P1-DNS-ZONES"

    runcheck "grep -R 'zone' $BIND_CONF 2>/dev/null" \
        "Bind9 zone declarations" \
        "P1-DNS-ZONES"

    runcheck "ls -R $BIND_LOG 2>/dev/null" \
        "Bind9 log directory" \
        "P1-DNS-LOGS"

    runcheck "find $BIND_CONF -type f -perm -o+w" \
        "World-writable Bind9 config files" \
        "P3-DNS-PERMS"

    runcheck "find $BIND_VAR -type f -perm -o+w" \
        "World-writable Bind9 zone/cache files" \
        "P3-DNS-PERMS"

    runcheck "grep -R 'allow-transfer' $BIND_CONF 2>/dev/null" \
        "Bind9 zone transfer configuration" \
        "P3-DNS-XFR"

    runcheck "grep -R 'allow-recursion' $BIND_CONF 2>/dev/null" \
        "Bind9 recursion ACL configuration" \
        "P3-DNS-RECURSION"
fi

# =====================================================================
#  UNBOUND ENUMERATION
# =====================================================================
if [ "$HAS_UNBOUND" -eq 1 ]; then
    runcheck "systemctl status unbound" \
        "Unbound service status" \
        "P1-DNS-DETECT"

    runcheck "unbound-checkconf $UNBOUND_MAIN_CONF" \
        "Unbound configuration check" \
        "P2-DNS-CONFFIX"

    runcheck "ls -R $UNBOUND_CONF" \
        "Unbound configuration directory" \
        "P1-DNS-CONF"

    runcheck "ls -R $UNBOUND_VAR" \
        "Unbound state/cache directory" \
        "P1-DNS-ZONES"

    runcheck "ls -R $UNBOUND_LOG 2>/dev/null" \
        "Unbound log directory" \
        "P1-DNS-LOGS"

    runcheck "find $UNBOUND_CONF -type f -perm -o+w" \
        "World-writable Unbound config files" \
        "P3-DNS-PERMS"

    runcheck "find $UNBOUND_VAR -type f -perm -o+w" \
        "World-writable Unbound state/cache files" \
        "P3-DNS-PERMS"

    runcheck "grep -R 'access-control:' $UNBOUND_CONF 2>/dev/null" \
        "Unbound recursion/access-control configuration" \
        "P3-DNS-RECURSION"
fi

# =====================================================================
#  DNSMASQ ENUMERATION
# =====================================================================
if [ "$HAS_DNSMASQ" -eq 1 ]; then
    runcheck "systemctl status dnsmasq" \
        "dnsmasq service status" \
        "P1-DNS-DETECT"

    runcheck "ls -R $DNSMASQ_CONF $DNSMASQ_D 2>/dev/null" \
        "dnsmasq configuration files" \
        "P1-DNS-CONF"

    runcheck "ls -R $DNSMASQ_VAR 2>/dev/null" \
        "dnsmasq lease/state directory" \
        "P1-DNS-ZONES"

    runcheck "ls -R $DNSMASQ_LOG 2>/dev/null" \
        "dnsmasq log file" \
        "P1-DNS-LOGS"

    runcheck "find $DNSMASQ_CONF $DNSMASQ_D -type f -perm -o+w 2>/dev/null" \
        "World-writable dnsmasq config files" \
        "P3-DNS-PERMS"
fi

# =====================================================================
#  ZONE & RESOLVER BEHAVIOR (GENERIC)
# =====================================================================
runcheck "dig @127.0.0.1 localhost || true" \
    "Local resolver test (loopback)" \
    "P1-DNS-RESOLVER"

runcheck "dig @8.8.8.8 google.com || true" \
    "External resolver test (Google DNS)" \
    "P1-DNS-RESOLVER"

runcheck "dig +dnssec @127.0.0.1 . SOA || true" \
    "DNSSEC validation test (root)" \
    "P3-DNS-DNSSEC"

runcheck "dig AXFR @127.0.0.1 example.com || true" \
    "Zone transfer (AXFR) test for example.com" \
    "P3-DNS-XFR"

# =====================================================================
#  PERMISSIONS & SECURITY (GENERIC)
# =====================================================================
runcheck "find $BIND_CONF $UNBOUND_CONF $DNSMASQ_CONF $DNSMASQ_D -maxdepth 5 -type d -exec ls -ld {} \; 2>/dev/null" \
    "DNS configuration directory permissions" \
    "P2-DNS-PERMS"

runcheck "find $BIND_CONF $UNBOUND_CONF $DNSMASQ_CONF $DNSMASQ_D -maxdepth 5 -type f -exec ls -l {} \; 2>/dev/null" \
    "DNS configuration file permissions" \
    "P2-DNS-PERMS"

# =====================================================================
#  FINALIZATION
# =====================================================================
log "=== DNS-RP-END ==="
