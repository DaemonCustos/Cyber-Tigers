#!/bin/sh
# =====================================================================
#  NCAE WEB ROLE PACK SCRIPT (UNIVERSAL • POSIX • AUTO-DETECT)
#  Supports: Nginx • Apache/HTTPD
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

OUTDIR="$HOME/ncae-web"
LOGDIR="$OUTDIR/logs"
TMPDIR="$OUTDIR/tmp"
OUTFILE="$OUTDIR/${HOSTNAME}-web-rp-$TS.txt"

mkdir -p "$OUTDIR" "$LOGDIR" "$TMPDIR" 2>/dev/null

# --- Logging ----------------------------------------------------------
log() {
    printf "%s\n" "$1" | tee -a "$OUTFILE"
}

log "=== WEB-RP-START ==="
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
log "--- Web Service Auto-Detection (P1-WEB-DETECT) ---"

HAS_NGINX=0
HAS_APACHE=0
HAS_WEB=0

if systemctl is-active --quiet nginx 2>/dev/null; then
    HAS_NGINX=1
    HAS_WEB=1
    WEB_SERVICE="nginx"
    log "Detected: NGINX"
elif systemctl is-active --quiet httpd 2>/dev/null; then
    HAS_APACHE=1
    HAS_WEB=1
    WEB_SERVICE="apache"
    log "Detected: APACHE/HTTPD"
else
    WEB_SERVICE="none"
    log "[RED] No active web service detected."
fi
log ""

# --- Service-Specific Paths ------------------------------------------
NGINX_CONF="/etc/nginx"
NGINX_WWW="/usr/share/nginx/html"
NGINX_LOG="/var/log/nginx"

APACHE_CONF="/etc/httpd"
APACHE_WWW="/var/www"
APACHE_LOG="/var/log/httpd"

if [ "$WEB_SERVICE" = "nginx" ]; then
    WEB_CONF_DIR="$NGINX_CONF"
    WEB_WWW_DIR="$NGINX_WWW"
    WEB_LOG_DIR="$NGINX_LOG"
elif [ "$WEB_SERVICE" = "apache" ]; then
    WEB_CONF_DIR="$APACHE_CONF"
    WEB_WWW_DIR="$APACHE_WWW"
    WEB_LOG_DIR="$APACHE_LOG"
else
    WEB_CONF_DIR="/etc"
    WEB_WWW_DIR="/var/www"
    WEB_LOG_DIR="/var/log"
fi

# =====================================================================
#  UNIVERSAL ENUMERATION
# =====================================================================
runcheck "ss -tulnp | grep -E ':80|:443'" \
    "Web ports (80/443) listening" \
    "P1-WEB-PORTS"

runcheck "ps -ef | grep -E 'nginx|httpd|apache' | grep -v grep" \
    "Web service processes" \
    "P1-WEB-DETECT"

runcheck "journalctl -u nginx -u httpd -n 200" \
    "Recent web service logs" \
    "P1-WEB-LOGS"

runcheck "iptables -L -n -v" \
    "Firewall exposure" \
    "P1-WEB-FW"

# =====================================================================
#  NGINX ENUMERATION
# =====================================================================
if [ "$HAS_NGINX" -eq 1 ]; then
    runcheck "nginx -T" \
        "Nginx full configuration dump" \
        "P1-WEB-CONFIG"

    runcheck "ls -R $NGINX_CONF" \
        "Nginx configuration directory" \
        "P1-WEB-CONFIG"

    runcheck "ls -R $NGINX_WWW" \
        "Nginx document root" \
        "P1-WEB-ROOTS"

    runcheck "find $NGINX_WWW -type f -name '*.bak' -o -name '*.old' -o -name '*.swp'" \
        "Backup/test files in Nginx web roots" \
        "P2-WEB-CLEAN"
fi

# =====================================================================
#  APACHE ENUMERATION
# =====================================================================
if [ "$HAS_APACHE" -eq 1 ]; then
    runcheck "apachectl -S" \
        "Apache vhost configuration" \
        "P1-WEB-CONFIG"

    runcheck "apachectl -M" \
        "Apache loaded modules" \
        "P3-WEB-MODULES"

    runcheck "ls -R $APACHE_CONF" \
        "Apache configuration directory" \
        "P1-WEB-CONFIG"

    runcheck "ls -R $APACHE_WWW" \
        "Apache document root" \
        "P1-WEB-ROOTS"

    runcheck "find $APACHE_WWW -type f -name '*.bak' -o -name '*.old' -o -name '*.swp'" \
        "Backup/test files in Apache web roots" \
        "P2-WEB-CLEAN"
fi

# =====================================================================
#  PERMISSIONS & SECURITY
# =====================================================================
runcheck "find $WEB_WWW_DIR -maxdepth 5 -type d -exec ls -ld {} \;" \
    "Directory permissions (web roots)" \
    "P2-WEB-PERMS"

runcheck "find $WEB_WWW_DIR -maxdepth 5 -type f -exec ls -l {} \;" \
    "File permissions (web roots)" \
    "P2-WEB-PERMS"

runcheck "find $WEB_WWW_DIR -type f -name '*.php~' -o -name '*.tmp' -o -name '*.save'" \
    "Dangerous leftover files" \
    "P2-WEB-CLEAN"

runcheck "grep -R 'Options Indexes' $WEB_CONF_DIR 2>/dev/null" \
    "Directory listing detection" \
    "P3-WEB-LISTING"

runcheck "grep -R 'autoindex on' $WEB_CONF_DIR 2>/dev/null" \
    "Nginx directory listing detection" \
    "P3-WEB-LISTING"

runcheck "find $WEB_WWW_DIR -type f -perm -o+w" \
    "World-writable files" \
    "P3-WEB-PERMS"

runcheck "find $WEB_WWW_DIR -type d -perm -o+w" \
    "World-writable directories" \
    "P3-WEB-PERMS"

runcheck "find $WEB_WWW_DIR -type f -executable" \
    "Unexpected executables in web root" \
    "P3-WEB-EXEC"

# =====================================================================
#  FINALIZATION
# =====================================================================
log "=== WEB-RP-END ==="
