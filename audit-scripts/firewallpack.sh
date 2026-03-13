#!/bin/sh

TS="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname)"
OUTDIR="$HOME/ncae-audits"
OUTFILE="$OUTDIR/${HOST}-firewall-rp-${TS}.txt"

mkdir -p "$OUTDIR"

log() {
    echo "===== $1 =====" >> "$OUTFILE"
}

flag_red() {
    echo "[RED] $1" >> "$OUTFILE"
}

flag_orange() {
    echo "[ORANGE] $1" >> "$OUTFILE"
}

flag_green() {
    echo "[GREEN] $1" >> "$OUTFILE"
}

runcheck() {
    log "$1"
    sh -c "$2" >> "$OUTFILE" 2>&1
    echo "" >> "$OUTFILE"
}

log "FIREWALL ROLE PACK SCRIPT START"
echo "" >> "$OUTFILE"

###############################################################################
# ENGINE DETECTION — P1-FW-ENGINE
###############################################################################

runcheck "iptables ruleset (filter) [P1-FW-ENGINE]" "iptables -L -n -v || true"
if iptables -L -n -v >/dev/null 2>&1; then
    flag_green "iptables filter table responding → [P1-FW-ENGINE]"
else
    flag_orange "iptables filter table not available → [P1-FW-ENGINE]"
fi

runcheck "iptables ruleset (raw) [P1-FW-ENGINE]" "iptables -t raw -L -n -v || true"
runcheck "iptables ruleset (mangle) [P1-FW-ENGINE]" "iptables -t mangle -L -n -v || true"
runcheck "iptables ruleset (security) [P1-FW-ENGINE]" "iptables -t security -L -n -v || true"
runcheck "iptables rule dump (-S) [P1-FW-ENGINE]" "iptables -S || true"
runcheck "iptables NAT rule dump (-S) [P1-FW-ENGINE]" "iptables -t nat -S || true"

runcheck "nftables list tables [P1-FW-ENGINE]" "nft list tables || true"
if nft list tables >/dev/null 2>&1; then
    flag_green "nftables tables responding → [P1-FW-ENGINE]"
fi

runcheck "nftables list chains [P1-FW-ENGINE]" "nft list chains || true"
runcheck "nftables full ruleset [P1-FW-ENGINE]" "nft list ruleset || true"
runcheck "nftables full ruleset with handles [P1-FW-ENGINE]" "nft list ruleset -a || true"

###############################################################################
# LISTENING PORTS / CONNECTIONS — P1-FW-BASE
###############################################################################

runcheck "Listening ports (IPv4/IPv6) [P1-FW-BASE]" "ss -tulnp || true"

runcheck "Established connections [P1-FW-BASE]" "ss -tanp | grep ESTAB || true"

runcheck "High‑port listeners (3000–9999) [P1-FW-BASE]" \
"ss -tulnp | awk '\$5 ~ /:[3-9][0-9]{3}\$/ {print}' || true"
if ss -tulnp | awk '$5 ~ /:[3-9][0-9]{3}$/' | grep -q .; then
    flag_orange "High‑port listeners detected (may be benign or suspicious) → [P1-FW-BASE]"
fi

runcheck "Known malicious ports [P1-FW-BASE]" \
"ss -tulnp | grep -E ':4444|:8081|:9001|:1337' || true"
if ss -tulnp | grep -E ':4444|:8081|:9001|:1337' >/dev/null 2>&1; then
    flag_red "Known attacker ports listening → [P1-FW-BASE]"
fi

###############################################################################
# SERVICE EXPOSURE CHECKS — P1-FW-SVC
###############################################################################

runcheck "SSH exposure [P1-FW-SSH]" "ss -tulnp | grep ':22' || true"
if ss -tulnp | grep ':22' >/dev/null 2>&1; then
    flag_green "SSH present as expected for firewall admin → [P1-FW-SSH]"
else
    flag_red "SSH missing or blocked; remote admin may be impossible → [P1-FW-SSH]"
fi

runcheck "FTP exposure [P1-FW-FTP]" "ss -tulnp | grep -E ':21|:20' || true"
if ss -tulnp | grep -E ':21|:20' >/dev/null 2>&1; then
    flag_red "FTP service exposed on firewall host → [P1-FW-FTP]"
fi

runcheck "Web exposure [P1-FW-WEB]" "ss -tulnp | grep -E ':80|:443' || true"
if ss -tulnp | grep -E ':80|:443' >/dev/null 2>&1; then
    flag_orange "Web service present on firewall (reverse proxy or UI?) → [P1-FW-WEB]"
fi

runcheck "Database exposure [P1-FW-DB]" "ss -tulnp | grep ':3306' || true"
if ss -tulnp | grep ':3306' >/dev/null 2>&1; then
    flag_red "Database port exposed on firewall host → [P1-FW-DB]"
fi

runcheck "DNS exposure [P1-FW-DNS]" "ss -tulnp | grep ':53' || true"
if ss -tulnp | grep ':53' >/dev/null 2>&1; then
    flag_orange "DNS service present on firewall (forwarder?) → [P1-FW-DNS]"
fi

###############################################################################
# IPV6 EXPOSURE — P1-FW-IPV6
###############################################################################

runcheck "IPv6 listeners [P1-FW-IPV6]" "ss -tulnp6 || true"
if ss -tulnp6 | grep -q . 2>/dev/null; then
    flag_orange "IPv6 listeners detected; verify exposure and rules → [P1-FW-IPV6]"
fi

runcheck "ip6tables ruleset [P1-FW-IPV6]" "ip6tables -L -n -v || true"
runcheck "ip6tables rule dump (-S) [P1-FW-IPV6]" "ip6tables -S || true"

###############################################################################
# FIREWALL SERVICES / STATE — P2-FW-ENGINE
###############################################################################

runcheck "firewalld status [P2-FW-ENGINE]" "systemctl status firewalld || true"
if systemctl is-active firewalld >/dev/null 2>&1; then
    flag_green "firewalld active → [P2-FW-ENGINE]"
fi

runcheck "firewalld enabled? [P2-FW-ENGINE]" "systemctl is-enabled firewalld || true"
if systemctl is-enabled firewalld 2>/dev/null | grep -q disabled; then
    flag_orange "firewalld installed but disabled → [P2-FW-ENGINE]"
fi

runcheck "ufw status [P2-FW-ENGINE]" "ufw status || true"
runcheck "ufw enabled? [P2-FW-ENGINE]" "systemctl is-enabled ufw || true"
if systemctl is-enabled ufw 2>/dev/null | grep -q enabled; then
    flag_orange "UFW enabled; verify it is intended firewall engine → [P2-FW-ENGINE]"
fi

runcheck "ufw raw rules [P2-FW-ENGINE]" "ufw show raw || true"

runcheck "nftables enabled? [P2-FW-ENGINE]" "systemctl is-enabled nftables || true"
if systemctl is-enabled nftables 2>/dev/null | grep -q enabled; then
    flag_green "nftables enabled → [P2-FW-ENGINE]"
fi

runcheck "iptables enabled? [P2-FW-ENGINE]" "systemctl is-enabled iptables || true"

runcheck "fail2ban status [P2-FW-ENGINE]" "systemctl status fail2ban || true"
if systemctl is-active fail2ban >/dev/null 2>&1; then
    flag_green "fail2ban active → [P2-FW-ENGINE]"
fi

###############################################################################
# KERNEL FORWARDING — P2-FW-FWD
###############################################################################

runcheck "IPv4 forwarding [P2-FW-FWD]" "sysctl net.ipv4.ip_forward"
if sysctl net.ipv4.ip_forward 2>/dev/null | grep -q ' = 1'; then
    flag_orange "IPv4 forwarding enabled; verify routing intent → [P2-FW-FWD]"
fi

runcheck "IPv6 forwarding [P2-FW-FWD]" "sysctl net.ipv6.conf.all.forwarding"
if sysctl net.ipv6.conf.all.forwarding 2>/dev/null | grep -q ' = 1'; then
    flag_orange "IPv6 forwarding enabled; verify routing intent → [P2-FW-FWD]"
fi

###############################################################################
# MODULE CHECKS — P2-FW-MODULES
###############################################################################

runcheck "Suspicious kernel modules [P2-FW-MODULES]" \
"lsmod | grep -E 'tun|tap|nf_nat|iptable_raw|xt_REDIRECT' || true"
if lsmod | grep -E 'tun|tap' >/dev/null 2>&1; then
    flag_orange "TUN/TAP modules loaded; possible VPN/tunnel usage → [P2-FW-MODULES]"
fi

###############################################################################
# PERSISTENCE CHECKS — P2-FW-RCLOCAL / P2-FW-CRON
###############################################################################

runcheck "rc.local firewall tampering (iptables) [P2-FW-RCLOCAL]" \
"grep -R 'iptables' /etc/rc.local 2>/dev/null || true"
if grep -R 'iptables' /etc/rc.local 2>/dev/null | grep -q .; then
    flag_red "rc.local contains iptables commands; possible persistence → [P2-FW-RCLOCAL]"
fi

runcheck "rc.local firewall tampering (nft) [P2-FW-RCLOCAL]" \
"grep -R 'nft' /etc/rc.local 2>/dev/null || true"
if grep -R 'nft' /etc/rc.local 2>/dev/null | grep -q .; then
    flag_red "rc.local contains nft commands; possible persistence → [P2-FW-RCLOCAL]"
fi

runcheck "systemd firewall units (iptables) [P2-FW-RCLOCAL]" \
"systemctl list-unit-files | grep iptables || true"

runcheck "systemd firewall units (nft) [P2-FW-RCLOCAL]" \
"systemctl list-unit-files | grep nft || true"

runcheck "cron firewall tampering (iptables) [P2-FW-CRON]" \
"grep -R 'iptables' /etc/cron* 2>/dev/null || true"
if grep -R 'iptables' /etc/cron* 2>/dev/null | grep -q .; then
    flag_red "Cron jobs contain iptables commands; possible persistence → [P2-FW-CRON]"
fi

runcheck "cron firewall tampering (nft) [P2-FW-CRON]" \
"grep -R 'nft' /etc/cron* 2>/dev/null || true"
if grep -R 'nft' /etc/cron* 2>/dev/null | grep -q .; then
    flag_red "Cron jobs contain nft commands; possible persistence → [P2-FW-CRON]"
fi

###############################################################################
# NAT BACKDOOR DETECTION — P2-FW-NAT
###############################################################################

runcheck "NAT PREROUTING [P2-FW-NAT]" "iptables -t nat -L PREROUTING -n -v || true"
runcheck "NAT OUTPUT [P2-FW-NAT]" "iptables -t nat -L OUTPUT -n -v || true"
if iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep -qi 'DNAT'; then
    flag_red "DNAT rules in PREROUTING; possible backdoor exposure → [P2-FW-NAT]"
fi

###############################################################################
# FIREWALLD ZONES — P3-FW-ZONES
###############################################################################

runcheck "firewalld active zones [P3-FW-ZONES]" \
"firewall-cmd --get-active-zones || true"

runcheck "firewalld all zones [P3-FW-ZONES]" \
"firewall-cmd --list-all-zones || true"

###############################################################################
# NFTABLES COUNTERS — P3-FW-NFTCNT
###############################################################################

runcheck "nftables counters [P3-FW-NFTCNT]" \
"nft list ruleset -a | grep -i counter || true"

###############################################################################
# END
###############################################################################

log "FIREWALL ROLE PACK SCRIPT COMPLETE"
echo "" >> "$OUTFILE"
