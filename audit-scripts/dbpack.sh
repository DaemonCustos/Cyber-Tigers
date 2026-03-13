#!/bin/sh

# ================================================================
#  DATABASE ROLE PACK — INITIALIZATION
# ================================================================
HOSTNAME=$(hostname 2>/dev/null || echo "unknown-host")
TS=$(date +"%Y%m%d-%H%M%S")
OUTDIR="$HOME/ncae-audits"
OUTFILE="$OUTDIR/${HOSTNAME}-dbpack-${TS}.txt"

mkdir -p "$OUTDIR"

log() {
    printf "%s\n" "$1" | tee -a "$OUTFILE"
}

runcheck() {
    CMD="$1"
    DESC="$2"
    REF="$3"
    PHASE="$4"

    log ""
    log "=== $DESC ==="
    log "REF: $REF"
    log "PHASE: $PHASE"
    log "CMD: $CMD"
    log "--- OUTPUT START ---"
    sh -c "$CMD" 2>&1 | tee -a "$OUTFILE"
    log "--- OUTPUT END ---"
}

log "=== DATABASE ROLE PACK START ==="
log "Hostname: $HOSTNAME"
log "Timestamp: $TS"
log "Output File: $OUTFILE"

# ================================================================
#  ENGINE DETECTION
# ================================================================
runcheck \
    "ps -ef | grep -E 'mariadb|mysql|mysqld' | grep -v grep" \
    "MariaDB/MySQL engine detection" \
    "DB-ENGINE-MYSQL" \
    "P1-DB-DETECT"

runcheck \
    "ps -ef | grep -E 'postgres|postgresql' | grep -v grep" \
    "PostgreSQL engine detection" \
    "DB-ENGINE-POSTGRES" \
    "P1-DB-DETECT"

# ================================================================
#  PORT & SOCKET VISIBILITY
# ================================================================
runcheck \
    "ss -tulnp | grep -E ':3306|:5432'" \
    "Database port visibility" \
    "DB-PORTS" \
    "P1-DB-PORTS"

runcheck \
    "find / -type s -name 'mysql.sock' 2>/dev/null; find / -type s -name '.s.PGSQL.5432' 2>/dev/null" \
    "Socket file discovery (full search)" \
    "DB-SOCKETS-DEEP" \
    "P1-DB-SOCKETS"

# ================================================================
#  CONFIG DIRECTORY VISIBILITY
# ================================================================
runcheck \
    "ls -R /etc/mysql 2>/dev/null; ls -R /etc/my.cnf* 2>/dev/null" \
    "MySQL/MariaDB config visibility" \
    "DB-CONF-MYSQL" \
    "P1-DB-CONF"

runcheck \
    "ls -R /etc/postgresql 2>/dev/null" \
    "PostgreSQL config visibility" \
    "DB-CONF-POSTGRES" \
    "P1-DB-CONF"

runcheck \
    "grep -R '' /etc/mysql /etc/my.cnf* 2>/dev/null" \
    "MySQL/MariaDB config content visibility" \
    "DB-CONF-MYSQL-CONTENT" \
    "P2-DB-CONF"

runcheck \
    "grep -R '' /etc/postgresql 2>/dev/null" \
    "PostgreSQL config content visibility" \
    "DB-CONF-POSTGRES-CONTENT" \
    "P2-DB-CONF"

# ================================================================
#  PLUGIN / MODULE VISIBILITY
# ================================================================
runcheck \
    "ls -R /usr/lib/mysql/plugin 2>/dev/null" \
    "MySQL/MariaDB plugin directory visibility" \
    "DB-PLUGIN-MYSQL" \
    "P3-DB-PLUGIN"

runcheck \
    "ls -R /usr/lib/postgresql 2>/dev/null" \
    "PostgreSQL module directory visibility" \
    "DB-PLUGIN-POSTGRES" \
    "P3-DB-PLUGIN"

# ================================================================
#  BIND-ADDRESS & IPV6 EXPOSURE
# ================================================================
runcheck \
    "grep -R 'bind-address' /etc/mysql /etc/my.cnf* 2>/dev/null" \
    "MySQL/MariaDB bind-address exposure" \
    "DB-BINDADDR-MYSQL" \
    "P3-DB-BIND"

runcheck \
    "grep -R 'listen_addresses' /etc/postgresql 2>/dev/null" \
    "PostgreSQL listen_addresses exposure" \
    "DB-BINDADDR-POSTGRES" \
    "P3-DB-BIND"

runcheck \
    "ss -tulnp | grep -E ':::3306|:::5432'" \
    "IPv6 wildcard exposure" \
    "DB-IPV6" \
    "P3-DB-IPV6"

# ================================================================
#  AUTHENTICATION MODE VISIBILITY
# ================================================================
runcheck \
    "grep -R 'auth_socket' /etc/mysql /etc/my.cnf* 2>/dev/null" \
    "MySQL/MariaDB authentication plugin visibility" \
    "DB-AUTH-MYSQL" \
    "P3-DB-AUTH"

runcheck \
    "grep -R 'scram-sha-256' /etc/postgresql 2>/dev/null" \
    "PostgreSQL authentication mode visibility" \
    "DB-AUTH-POSTGRES" \
    "P3-DB-AUTH"

# ================================================================
#  ANONYMOUS / TEST DATABASE VISIBILITY (SAFE)
# ================================================================
runcheck \
    "mysql -e 'SELECT User,Host FROM mysql.user;' 2>/dev/null" \
    "MySQL/MariaDB user visibility" \
    "DB-USERS-MYSQL" \
    "P3-DB-USERS"

runcheck \
    "psql -c '\du' 2>/dev/null" \
    "PostgreSQL user visibility" \
    "DB-USERS-POSTGRES" \
    "P3-DB-USERS"

runcheck \
    "mysql -e 'SHOW DATABASES;' 2>/dev/null" \
    "MySQL/MariaDB database visibility" \
    "DB-DBS-MYSQL" \
    "P3-DB-DBS"

runcheck \
    "psql -l 2>/dev/null" \
    "PostgreSQL database visibility" \
    "DB-DBS-POSTGRES" \
    "P3-DB-DBS"

# ================================================================
#  PERMISSIONS & OWNERSHIP VISIBILITY
# ================================================================
runcheck \
    "find /var/lib/mysql -type f -perm -o+w 2>/dev/null" \
    "MySQL/MariaDB world-writable files" \
    "DB-PERMS-MYSQL" \
    "P3-DB-PERMS"

runcheck \
    "find /var/lib/postgresql -type f -perm -o+w 2>/dev/null" \
    "PostgreSQL world-writable files" \
    "DB-PERMS-POSTGRES" \
    "P3-DB-PERMS"

runcheck \
    "ls -ld /var/lib/mysql 2>/dev/null; ls -ld /var/lib/postgresql 2>/dev/null" \
    "Database directory ownership" \
    "DB-DIR-PERMS" \
    "P3-DB-PERMS"

# ================================================================
#  POSTGRESQL HBA VISIBILITY
# ================================================================
runcheck \
    "grep -R '' /etc/postgresql/*/*/pg_hba.conf 2>/dev/null" \
    "PostgreSQL pg_hba.conf visibility" \
    "DB-HBA" \
    "P3-DB-HBA"

# ================================================================
#  LOGGING VISIBILITY
# ================================================================
runcheck \
    "ls -R /var/log/mysql 2>/dev/null; ls -R /var/log/mariadb 2>/dev/null" \
    "MySQL/MariaDB logging visibility" \
    "DB-LOGS-MYSQL" \
    "P2-DB-LOGS"

runcheck \
    "ls -R /var/log/postgresql 2>/dev/null" \
    "PostgreSQL logging visibility" \
    "DB-LOGS-POSTGRES" \
    "P2-DB-LOGS"

# ================================================================
#  STARTUP STATE
# ================================================================
runcheck \
    "systemctl is-enabled mariadb 2>/dev/null; systemctl is-enabled mysql 2>/dev/null" \
    "MySQL/MariaDB startup state" \
    "DB-STARTUP-MYSQL" \
    "P2-DB-SVC"

runcheck \
    "systemctl is-enabled postgresql 2>/dev/null" \
    "PostgreSQL startup state" \
    "DB-STARTUP-POSTGRES" \
    "P2-DB-SVC"

# ================================================================
#  FINALIZATION
# ================================================================
log "=== DATABASE ROLE PACK END ==="
