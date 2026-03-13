#!/bin/sh
# =====================================================================
#  NCAE SCANNING ROLE PACK — LINUX (READ‑ONLY, SAFE)
#  Deep listener analysis • Dangerous daemon detection • Kali‑aware
# =====================================================================

HOSTNAME="$(hostname 2>/dev/null || echo unknown-host)"
TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$HOME/ncae-audits"
OUTFILE="$OUTDIR/${HOSTNAME}-scanpack-$TS.txt"

mkdir -p "$OUTDIR" 2>/dev/null

log() {
    printf "%s\n" "$1" | tee -a "$OUTFILE"
}

log "=== SCANPACK-START ==="
log "Host: $HOSTNAME"
log "Timestamp: $TS"
log ""

# =====================================================================
#  COLOR FLAGS
# =====================================================================
RED="[RED]"
ORANGE="[ORANGE]"
GREEN="[GREEN]"

# =====================================================================
#  LISTENING PORTS (DEEP ENUMERATION)
# =====================================================================
log "--- Listening Ports (SCAN-AUDIT-LISTEN) ---"
log "REF: P1-SCAN-LISTEN"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>&1 | tee -a "$OUTFILE"
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnp 2>&1 | tee -a "$OUTFILE"
else
    log "$ORANGE No ss or netstat available."
fi
log ""

# =====================================================================
#  UNEXPECTED LISTENERS (COMMON DANGEROUS PORTS)
# =====================================================================
log "--- Unexpected Listener Scan (SCAN-AUDIT-UNEXPECTED-LISTEN) ---"
log "REF: P3-SCAN-DANGER"
DANGEROUS_PORTS="21 23 69 111 512 513 514 873 3306 5900 6000"

for P in $DANGEROUS_PORTS; do
    if ss -tulnp 2>/dev/null | grep -q ":$P "; then
        log "$RED Port $P is listening (unexpected/high-risk)"
    fi
done
log ""

# =====================================================================
#  DANGEROUS DAEMON DETECTION
# =====================================================================
log "--- Dangerous Daemon Detection (SCAN-AUDIT-DANGER-DAEMON) ---"
log "REF: P3-SCAN-DANGER"
ps -ef | grep -E "telnetd|vsftpd|tftp|rsh|rlogin|xinetd" | grep -v grep | tee -a "$OUTFILE"
log ""

# =====================================================================
#  ADVANCED DAEMON / PROCESS ENUMERATION (RED-TEAM RESISTANT)
# =====================================================================
log "--- Advanced Daemon / Process Enumeration (SCAN-AUDIT-ADV-DAEMON) ---"
log "REF: P3-SCAN-SUSPATH"

# 1. Processes running from suspicious directories
log "Suspicious Execution Paths (SCAN-AUDIT-SUSPATH) ---"
log "REF: P3-SCAN-SUSPATH"
ps -eo pid,user,cmd --sort=cmd 2>/dev/null | grep -E "/tmp|/var/tmp|/dev/shm|/home" | grep -v grep | tee -a "$OUTFILE"
log ""

# 2. Processes with deleted executables
log "Deleted Executables (SCAN-AUDIT-DELETED) ---"
log "REF: P3-SCAN-DELETED"
ls -l /proc/*/exe 2>/dev/null | grep deleted | tee -a "$OUTFILE"
log ""

# 3. Interpreter-based daemons
log "Interpreter-Based Daemons (SCAN-AUDIT-INTERP) ---"
log "REF: P3-SCAN-INTERP"
ps -ef | grep -E "python|perl|php|node|ruby" | grep -v grep | tee -a "$OUTFILE"
log ""

# 4. Unknown network-backed processes
log "Unknown Network-Backed Processes (SCAN-AUDIT-NETBACKED) ---"
log "REF: P3-SCAN-DANGER"
ss -tulnp 2>/dev/null | grep -E "users:\(\(\"[^\"]*\",pid=[0-9]+" | while read -r line; do
    PID=$(echo "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
    if [ -n "$PID" ]; then
        CMD=$(ps -p "$PID" -o cmd= 2>/dev/null)
        if ! echo "$CMD" | grep -Eq "nginx|apache|sshd|named|dhcpd|mysql|mariadb|systemd"; then
            log "$RED Suspicious network process: PID $PID — $CMD"
        fi
    fi
done
log ""

# 5. Unpackaged binaries
log "Unpackaged Processes (SCAN-AUDIT-UNPACKAGED) ---"
log "REF: P2-SCAN-DAEMONFIX"
if command -v dpkg >/dev/null 2>&1; then
    log "Unpackaged Processes (Debian/Ubuntu):"
    for PID in $(ps -e -o pid=); do
        EXE=$(readlink -f /proc/$PID/exe 2>/dev/null)
        if [ -n "$EXE" ] && ! dpkg -S "$EXE" >/dev/null 2>&1; then
            CMD=$(ps -p "$PID" -o cmd=)
            log "$ORANGE Unpackaged binary: PID $PID — $CMD"
        fi
    done
fi

if command -v rpm >/dev/null 2>&1; then
    log "Unpackaged Processes (RPM-based):"
    for PID in $(ps -e -o pid=); do
        EXE=$(readlink -f /proc/$PID/exe 2>/dev/null)
        if [ -n "$EXE" ] && ! rpm -qf "$EXE" >/dev/null 2>&1; then
            CMD=$(ps -p "$PID" -o cmd=)
            log "$ORANGE Unpackaged binary: PID $PID — $CMD"
        fi
    done
fi
log ""

# 6. Linux capabilities
log "Processes with Linux Capabilities (SCAN-AUDIT-CAPS) ---"
log "REF: P3-SCAN-DANGER"
if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null | tee -a "$OUTFILE"
fi
log ""

# 7. Processes without systemd units
log "Processes Without Matching systemd Units (SCAN-AUDIT-NO-UNIT) ---"
log "REF: P2-SCAN-DAEMONFIX"
for PID in $(ps -e -o pid=); do
    UNIT=$(systemctl status "$PID" 2>/dev/null | grep Loaded)
    if [ -z "$UNIT" ]; then
        CMD=$(ps -p "$PID" -o cmd=)
        log "$ORANGE No systemd unit: PID $PID — $CMD"
    fi
done
log ""

# =====================================================================
#  PARTIAL IMPLEMENTATION DETECTION
# =====================================================================

log "--- Partial Implementation: DNS (SCAN-AUDIT-DNS-PARTIAL) ---"
log "REF: P2-SCAN-DNSFIX"
systemctl status bind9 2>/dev/null | grep Active | tee -a "$OUTFILE"
systemctl status named 2>/dev/null | grep Active | tee -a "$OUTFILE"
log ""

log "--- Partial Implementation: DHCP (SCAN-AUDIT-DHCP-PARTIAL) ---"
log "REF: P2-SCAN-DHCPCHECK"
systemctl status isc-dhcp-server 2>/dev/null | grep Active | tee -a "$OUTFILE"
log ""

log "--- Partial Implementation: Web Server (SCAN-AUDIT-WEB-PARTIAL) ---"
log "REF: P2-SCAN-WEBFIX"
systemctl status nginx 2>/dev/null | grep Active | tee -a "$OUTFILE"
systemctl status apache2 2>/dev/null | grep Active | tee -a "$OUTFILE"
log ""

log "--- Partial Implementation: Database (SCAN-AUDIT-DB-PARTIAL) ---"
log "REF: P2-SCAN-DBFIX"
systemctl status mariadb 2>/dev/null | grep Active | tee -a "$OUTFILE"
systemctl status mysql 2>/dev/null | grep Active | tee -a "$OUTFILE"
log ""

log "--- Partial Implementation: SSH (SCAN-AUDIT-SSH-PARTIAL) ---"
log "REF: P2-SCAN-DAEMONFIX"
grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | tee -a "$OUTFILE"
log ""

# =====================================================================
#  FIREWALL EXPOSURE
# =====================================================================
log "--- Firewall Exposure (SCAN-AUDIT-FW) ---"
log "REF: P1-SCAN-FWVIS"
if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --list-all 2>&1 | tee -a "$OUTFILE"
fi

if command -v ufw >/dev/null 2>&1; then
    ufw status verbose 2>&1 | tee -a "$OUTFILE"
fi

if command -v iptables >/dev/null 2>&1; then
    iptables -L -n -v 2>&1 | tee -a "$OUTFILE"
fi

if command -v nft >/dev/null 2>&1; then
    nft list ruleset 2>&1 | tee -a "$OUTFILE"
fi
log ""

# =====================================================================
#  IPV6 EXPOSURE
# =====================================================================
log "--- IPv6 Exposure (SCAN-AUDIT-IPV6) ---"
log "REF: P3-SCAN-KERN"
ip -6 addr show 2>/dev/null | tee -a "$OUTFILE"
ip -6 route show 2>/dev/null | tee -a "$OUTFILE"
log ""

# =====================================================================
#  THIRD-PARTY SECURITY PRODUCTS
# =====================================================================
log "--- Third-Party Security Products (SCAN-AUDIT-SEC-PRODUCTS) ---"
log "REF: P2-SCAN-DAEMONFIX"
ps -ef | grep -E "crowdstrike|falcon|sentinel|sophos|clamd" | grep -v grep | tee -a "$OUTFILE"
log ""

# =====================================================================
#  SYSTEMD SERVICE EXPOSURE
# =====================================================================
log "--- Running Services (SCAN-AUDIT-SYSTEMD) ---"
log "REF: P2-SCAN-DAEMONFIX"
systemctl list-units --type=service --state=running 2>/dev/null | tee -a "$OUTFILE"
log ""

# =====================================================================
#  CRON/TIMER EXPOSURE
# =====================================================================
log "--- Cron & Timer Exposure (SCAN-AUDIT-CRON) ---"
log "REF: P2-SCAN-DAEMONFIX"
crontab -l 2>/dev/null | tee -a "$OUTFILE"
ls -l /etc/cron* 2>/dev/null | tee -a "$OUTFILE"
systemctl list-timers 2>/dev/null | tee -a "$OUTFILE"
log ""

# =====================================================================
#  KERNEL FORWARDING STATE
# =====================================================================
log "--- Kernel Forwarding State (SCAN-AUDIT-KERN) ---"
log "REF: P3-SCAN-KERN"
sysctl net.ipv4.ip_forward 2>/dev/null | tee -a "$OUTFILE"
sysctl net.ipv6.conf.all.forwarding 2>/dev/null | tee -a "$OUTFILE"
log ""

# =====================================================================
#  OPTIONAL KALI NMAP SCANNING
# =====================================================================
log "--- Optional Kali Nmap Scanning (SCAN-AUDIT-NMAP) ---"
log "REF: P1-SCAN-TOOLS"
if grep -qi "kali" /etc/os-release 2>/dev/null; then
    log "--- Kali Linux Detected ---"
    log "Enable Nmap scanning? (yes/no)"
    read -r ANSWER

    if [ "$ANSWER" = "yes" ] || [ "$ANSWER" = "y" ]; then
        log "--- Nmap Host Discovery ---"
        nmap -sn 10.0.0.0/24 2>&1 | tee -a "$OUTFILE"

        log "--- Nmap TCP Connect Scan ---"
        nmap -sT 10.0.0.0/24 2>&1 | tee -a "$OUTFILE"

        log "--- Nmap Version Detection ---"
        nmap -sV 10.0.0.0/24 2>&1 | tee -a "$OUTFILE"
    else
        log "Nmap scanning disabled."
    fi
fi

# =====================================================================
#  FINALIZATION
# =====================================================================
log "=== SCANPACK-END ==="
