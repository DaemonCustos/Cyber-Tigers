#!/bin/sh

TS="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname)"
OUTDIR="$HOME/ncae-audits"
OUTFILE="$OUTDIR/${HOST}-backup-rp-${TS}.txt"

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

log "BACKUP ROLE PACK SCRIPT START"
echo "" >> "$OUTFILE"

###############################################################################
# BACKUP ENGINE DETECTION — P1-BK-DETECT
###############################################################################

runcheck "Detect rsync binary [P1-BK-DETECT]" "command -v rsync || true"
if command -v rsync >/dev/null 2>&1; then
    flag_green "rsync present as expected for backup role → [P1-BK-DETECT]"
else
    flag_orange "rsync not found; rsync-based backups unavailable → [P1-BK-DETECT]"
fi

runcheck "Detect tar binary [P1-BK-DETECT]" "command -v tar || true"
if command -v tar >/dev/null 2>&1; then
    flag_green "tar present as expected for archive backups → [P1-BK-DETECT]"
else
    flag_orange "tar not found; tar-based backups unavailable → [P1-BK-DETECT]"
fi

runcheck "Detect LVM tools [P1-BK-DETECT]" "command -v lvs || true"
if command -v lvs >/dev/null 2>&1; then
    flag_orange "LVM tools present; snapshot backups possible → [P1-BK-DETECT]"
fi

runcheck "Detect ZFS tools [P1-BK-DETECT]" "command -v zfs || true"
if command -v zfs >/dev/null 2>&1; then
    flag_orange "ZFS tools present; ZFS snapshot backups possible → [P1-BK-DETECT]"
fi

###############################################################################
# RSYNC BACKUP DISCOVERY — P1-BK-RSYNC
###############################################################################

runcheck "Search for rsync backup scripts in system paths [P1-BK-RSYNC]" \
"grep -R \"rsync\" /etc /usr/local /opt /root 2>/dev/null || true"
if grep -R "rsync" /etc /usr/local /opt /root 2>/dev/null | grep -q .; then
    flag_green "rsync usage detected in system paths; verify backup intent → [P1-BK-RSYNC]"
fi

runcheck "Search for rsync backup scripts in home directories [P1-BK-RSYNC]" \
"grep -R \"rsync\" /home 2>/dev/null || true"
if grep -R "rsync" /home 2>/dev/null | grep -q .; then
    flag_orange "rsync usage in home directories; user-managed backups or exfil → [P1-BK-RSYNC]"
fi

runcheck "Search for rsync cron jobs [P1-BK-RSYNC]" \
"grep -R \"rsync\" /etc/cron* 2>/dev/null || true"
if grep -R "rsync" /etc/cron* 2>/dev/null | grep -q .; then
    flag_green "Scheduled rsync jobs detected; verify schedule and destinations → [P1-BK-RSYNC]"
fi

runcheck "Search for rsync systemd units [P1-BK-RSYNC]" \
"systemctl list-unit-files | grep -i rsync || true"
if systemctl list-unit-files | grep -i rsync >/dev/null 2>&1; then
    flag_orange "rsync-related systemd units present; verify configuration → [P1-BK-RSYNC]"
fi

runcheck "Search for exfiltration-like rsync commands [P1-BK-RSYNC]" \
"grep -R \"rsync .*@\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "rsync .*@" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "rsync to remote hosts detected; possible exfiltration → [P1-BK-RSYNC]"
fi

###############################################################################
# TAR BACKUP DISCOVERY — P1-BK-TAR
###############################################################################

runcheck "Search for tar backup scripts [P1-BK-TAR]" \
"grep -R \"tar .* -c\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "tar .* -c" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_green "tar-based backup scripts detected; verify paths and retention → [P1-BK-TAR]"
fi

runcheck "Search for tar archives (shallow) [P1-BK-TAR]" \
"find / -maxdepth 4 -type f \( -name \"*.tar\" -o -name \"*.tar.gz\" -o -name \"*.tgz\" \) 2>/dev/null || true"
if find / -maxdepth 4 -type f \( -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" \) 2>/dev/null | grep -q .; then
    flag_green "Tar archives present; verify freshness and integrity → [P1-BK-TAR]"
fi

###############################################################################
# LVM SNAPSHOT DISCOVERY — P1-BK-LVM
###############################################################################

runcheck "List LVM volumes [P1-BK-LVM]" "lvs || true"
if lvs >/dev/null 2>&1; then
    flag_orange "LVM volumes detected; snapshot backups may be in use → [P1-BK-LVM]"
fi

runcheck "List LVM snapshots by attribute [P1-BK-LVM]" \
"lvs --options lv_name,lv_attr | grep 's' || true"
if lvs --options lv_name,lv_attr 2>/dev/null | grep 's' >/dev/null 2>&1; then
    flag_green "LVM snapshots present; verify purpose and retention → [P1-BK-LVM]"
fi

runcheck "List LVM snapshots with origin [P1-BK-LVM]" \
"lvs --options lv_name,lv_attr,origin || true"

runcheck "List LVM snapshot timestamps [P1-BK-LVM]" \
"lvs --options lv_name,lv_time,lv_attr | grep 's' || true"

###############################################################################
# ZFS SNAPSHOT DISCOVERY — P1-BK-ZFS
###############################################################################

runcheck "List ZFS pools [P1-BK-ZFS]" "zpool list || true"
if zpool list >/dev/null 2>&1; then
    flag_orange "ZFS pools detected; ZFS-based backups possible → [P1-BK-ZFS]"
fi

runcheck "List ZFS datasets [P1-BK-ZFS]" "zfs list || true"

runcheck "List ZFS snapshots [P1-BK-ZFS]" "zfs list -t snapshot || true"
if zfs list -t snapshot >/dev/null 2>&1; then
    flag_green "ZFS snapshots present; verify backup policy and retention → [P1-BK-ZFS]"
fi

runcheck "List ZFS snapshots with creation and used [P1-BK-ZFS]" \
"zfs list -t snapshot -o name,creation,used || true"

###############################################################################
# BACKUP DESTINATION DISCOVERY — P1-BK-DEST
###############################################################################

runcheck "Mounted filesystems [P1-BK-DEST]" "mount || true"

runcheck "Detect NFS mounts [P1-BK-DEST]" "mount | grep -i nfs || true"
if mount | grep -i nfs >/dev/null 2>&1; then
    flag_orange "NFS mounts detected; verify backup destinations and exposure → [P1-BK-DEST]"
fi

runcheck "Detect SMB/CIFS mounts [P1-BK-DEST]" "mount | grep -i cifs || true"
if mount | grep -i cifs >/dev/null 2>&1; then
    flag_orange "SMB/CIFS mounts detected; verify backup destinations and access control → [P1-BK-DEST]"
fi

runcheck "Search for backup directories (shallow) [P1-BK-DEST]" \
"find / -maxdepth 3 -type d \( -name \"backup\" -o -name \"backups\" -o -name \"backup-*\" \) 2>/dev/null || true"
if find / -maxdepth 3 -type d \( -name "backup" -o -name "backups" -o -name "backup-*" \) 2>/dev/null | grep -q .; then
    flag_green "Backup directories detected; verify ownership and permissions → [P1-BK-DEST]"
fi

runcheck "Disk usage of common backup paths [P1-BK-DEST]" \
"du -sh /backup /backups /var/backups 2>/dev/null || true"

###############################################################################
# BACKUP LOG DISCOVERY — P1-BK-LOGS
###############################################################################

runcheck "Search for backup logs in /var/log [P1-BK-LOGS]" \
"find /var/log -type f -iname \"*backup*\" 2>/dev/null || true"
if find /var/log -type f -iname "*backup*" 2>/dev/null | grep -q .; then
    flag_green "Backup-related logs found in /var/log → [P1-BK-LOGS]"
fi

runcheck "Search for backup logs elsewhere [P1-BK-LOGS]" \
"find / -maxdepth 5 -type f -iname \"*backup*.log\" 2>/dev/null || true"

###############################################################################
# CRON + SYSTEMD BACKUP SCHEDULE DISCOVERY — P1-BK-CRON
###############################################################################

runcheck "Cron jobs referencing backups [P1-BK-CRON]" \
"grep -R -i \"backup\" /etc/cron* 2>/dev/null || true"
if grep -R -i "backup" /etc/cron* 2>/dev/null | grep -q .; then
    flag_green "Backup-related cron jobs detected; verify schedule and commands → [P1-BK-CRON]"
fi

runcheck "Cron jobs referencing rsync/tar [P1-BK-CRON]" \
"grep -R -E \"rsync|tar\" /etc/cron* 2>/dev/null || true"

runcheck "Systemd timers referencing backups [P1-BK-CRON]" \
"systemctl list-timers --all | grep -i backup || true"
if systemctl list-timers --all | grep -i backup >/dev/null 2>&1; then
    flag_green "Backup-related systemd timers detected; verify units and commands → [P1-BK-CRON]"
fi

runcheck "Systemd units referencing backups [P1-BK-CRON]" \
"systemctl list-unit-files | grep -i backup || true"

###############################################################################
# DEEP BACKUP SCRIPT ENUMERATION — P1-BK-DEEP
###############################################################################

runcheck "Find files named *backup* in system paths [P1-BK-DEEP]" \
"find /etc /usr/local /opt /root -maxdepth 6 -type f -iname \"*backup*\" 2>/dev/null || true"
if find /etc /usr/local /opt /root -maxdepth 6 -type f -iname "*backup*" 2>/dev/null | grep -q .; then
    flag_orange "Backup-named files in system paths; verify legitimacy → [P1-BK-DEEP]"
fi

runcheck "Find files named *backup* in home directories [P1-BK-DEEP]" \
"find /home -maxdepth 5 -type f -iname \"*backup*\" 2>/dev/null || true"
if find /home -maxdepth 5 -type f -iname "*backup*" 2>/dev/null | grep -q .; then
    flag_orange "Backup-named files in home directories; user scripts or possible exfil → [P1-BK-DEEP]"
fi

runcheck "Search for scp-based backup/exfil scripts [P1-BK-DEEP]" \
"grep -R \"scp .*@\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "scp .*@" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "scp to remote hosts in backup-like scripts; likely exfil → [P1-BK-DEEP]"
fi

runcheck "Search for curl-based backup/exfil scripts [P1-BK-DEEP]" \
"grep -R \"curl \" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "curl " /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "curl usage in backup-like scripts; possible HTTP exfil → [P1-BK-DEEP]"
fi

runcheck "Search for wget-based backup/exfil scripts [P1-BK-DEEP]" \
"grep -R \"wget \" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "wget " /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "wget usage in backup-like scripts; possible HTTP exfil → [P1-BK-DEEP]"
fi

###############################################################################
# BACKUP EXFILTRATION DETECTION — P1-BK-EXFIL
###############################################################################

runcheck "Search for rsync to remote hosts [P1-BK-EXFIL]" \
"grep -R \"rsync .*@\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "rsync .*@" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "rsync to remote hosts detected; high exfil risk → [P1-BK-EXFIL]"
fi

runcheck "Search for scp to remote hosts [P1-BK-EXFIL]" \
"grep -R \"scp .*@\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "scp .*@" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "scp to remote hosts detected; high exfil risk → [P1-BK-EXFIL]"
fi

runcheck "Search for sftp to remote hosts [P1-BK-EXFIL]" \
"grep -R \"sftp .*@\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "sftp .*@" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "sftp to remote hosts detected; high exfil risk → [P1-BK-EXFIL]"
fi

runcheck "Search for HTTP(S) upload in backup scripts [P1-BK-EXFIL]" \
"grep -R -E \"curl .*http|wget .*http\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R -E "curl .*http|wget .*http" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "HTTP(S) upload patterns in backup scripts; exfil likely → [P1-BK-EXFIL]"
fi

###############################################################################
# WORLD-WRITABLE BACKUP PATHS — P1-BK-WRITE
###############################################################################

runcheck "World-writable backup directories [P1-BK-WRITE]" \
"find / -maxdepth 5 -type d -perm -0002 -iname \"*backup*\" 2>/dev/null || true"
if find / -maxdepth 5 -type d -perm -0002 -iname "*backup*" 2>/dev/null | grep -q .; then
    flag_red "World-writable backup directories; high tampering risk → [P1-BK-WRITE]"
fi

runcheck "Backup directories in /tmp or /dev/shm [P1-BK-WRITE]" \
"find /tmp /dev/shm -maxdepth 4 -type d -iname \"*backup*\" 2>/dev/null || true"
if find /tmp /dev/shm -maxdepth 4 -type d -iname "*backup*" 2>/dev/null | grep -q .; then
    flag_red "Backup directories in /tmp or /dev/shm; likely attacker-controlled → [P1-BK-WRITE]"
fi

###############################################################################
# DANGEROUS REMOTE DESTINATIONS — P1-BK-REMOTE
###############################################################################

runcheck "Backup scripts referencing rsync:// [P1-BK-REMOTE]" \
"grep -R \"rsync://\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "rsync://" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "rsync:// destinations in backup scripts; verify remote endpoints → [P1-BK-REMOTE]"
fi

runcheck "Backup scripts referencing smb:// or cifs [P1-BK-REMOTE]" \
"grep -R -E \"smb://|cifs\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R -E "smb://|cifs" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_orange "SMB/CIFS remote backup destinations; verify trust and access → [P1-BK-REMOTE]"
fi

runcheck "Backup scripts referencing nfs:// [P1-BK-REMOTE]" \
"grep -R \"nfs://\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "nfs://" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_orange "NFS remote backup destinations; verify trust and access → [P1-BK-REMOTE]"
fi

runcheck "Backup scripts referencing http(s):// [P1-BK-REMOTE]" \
"grep -R -E \"http://|https://\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R -E "http://|https://" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "HTTP(S) remote backup destinations; possible exfil → [P1-BK-REMOTE]"
fi

###############################################################################
# CRON PERSISTENCE BEYOND BACKUPS — P1-BK-CRONPERSIST
###############################################################################

runcheck "Cron jobs with curl/wget [P1-BK-CRONPERSIST]" \
"grep -R -E \"curl |wget \" /etc/cron* 2>/dev/null || true"
if grep -R -E "curl |wget " /etc/cron* 2>/dev/null | grep -q .; then
    flag_red "Cron jobs using curl/wget; likely exfil or C2 → [P1-BK-CRONPERSIST]"
fi

runcheck "Cron jobs with bash -i or nc [P1-BK-CRONPERSIST]" \
"grep -R -E \"bash -i| nc \" /etc/cron* 2>/dev/null || true"
if grep -R -E "bash -i| nc " /etc/cron* 2>/dev/null | grep -q .; then
    flag_red "Cron jobs with reverse shell patterns; persistence → [P1-BK-CRONPERSIST]"
fi

###############################################################################
# SYSTEMD PERSISTENCE BEYOND BACKUPS — P1-BK-SYSPERSIST
###############################################################################

runcheck "Systemd units with suspicious backup names [P1-BK-SYSPERSIST]" \
"systemctl list-unit-files | grep -Ei \"backup|sync|archive\" || true"
if systemctl list-unit-files | grep -Ei "backup|sync|archive" >/dev/null 2>&1; then
    flag_orange "Systemd units with backup-like names; verify commands → [P1-BK-SYSPERSIST]"
fi

runcheck "Systemd timers with suspicious backup names [P1-BK-SYSPERSIST]" \
"systemctl list-timers --all | grep -Ei \"backup|sync|archive\" || true"
if systemctl list-timers --all | grep -Ei "backup|sync|archive" >/dev/null 2>&1; then
    flag_orange "Systemd timers with backup-like names; verify units → [P1-BK-SYSPERSIST]"
fi

###############################################################################
# LVM SNAPSHOT ABUSE — P1-BK-LVMABUSE
###############################################################################

runcheck "LVM snapshots with origin and time [P1-BK-LVMABUSE]" \
"lvs --options lv_name,lv_attr,origin,lv_time | grep 's' || true"
if lvs --options lv_name,lv_attr,origin,lv_time 2>/dev/null | grep 's' >/dev/null 2>&1; then
    flag_orange "LVM snapshots present; verify they are legitimate backups → [P1-BK-LVMABUSE]"
fi

runcheck "All LVM volumes with attributes [P1-BK-LVMABUSE]" \
"lvs --options vg_name,lv_name,lv_attr,lv_size,origin || true"

###############################################################################
# ZFS SNAPSHOT ABUSE — P1-BK-ZFSABUSE
###############################################################################

runcheck "ZFS snapshots with creation and used [P1-BK-ZFSABUSE]" \
"zfs list -t snapshot -o name,creation,used || true"
if zfs list -t snapshot -o name,creation,used >/dev/null 2>&1; then
    flag_orange "ZFS snapshots present; verify they are legitimate backups → [P1-BK-ZFSABUSE]"
fi

runcheck "ZFS snapshot properties [P1-BK-ZFSABUSE]" \
"zfs get all | grep -i snapshot || true"

###############################################################################
# BACKUP ARCHIVE INTEGRITY — P1-BK-INTEGRITY
###############################################################################

runcheck "Small tar archives (possible bogus backups) [P1-BK-INTEGRITY]" \
"find / -type f -name \"*.tar\" -size -10M -printf \"%s %p\n\" 2>/dev/null || true"
if find / -type f -name "*.tar" -size -10M -printf "%s %p\n" 2>/dev/null | grep -q .; then
    flag_orange "Very small tar archives; verify they are real backups → [P1-BK-INTEGRITY]"
fi

runcheck "List tar archive contents (non-destructive) [P1-BK-INTEGRITY]" \
"for f in \$(find / -type f -name \"*.tar\" 2>/dev/null | head -n 5); do echo \"--- \$f ---\"; tar -tf \"\$f\" 2>/dev/null | head -n 20; echo \"\"; done"

runcheck "Stat common backup archives [P1-BK-INTEGRITY]" \
"for f in /backup/*.tar /backups/*.tar /var/backups/*.tar 2>/dev/null; do [ -f \"\$f\" ] && stat \"\$f\"; done"

###############################################################################
# BACKUP SIZE ANOMALIES — P1-BK-SIZE
###############################################################################

runcheck "Disk usage of backup directories [P1-BK-SIZE]" \
"du -sh /backup /backups /var/backups 2>/dev/null || true"

runcheck "Tar archive sizes [P1-BK-SIZE]" \
"find / -type f -name \"*.tar*\" -printf \"%s %p\n\" 2>/dev/null || true"

###############################################################################
# BACKUP SCRIPT PERMISSIONS — P1-BK-PERMS
###############################################################################

runcheck "World-writable backup scripts [P1-BK-PERMS]" \
"find / -maxdepth 7 -type f -iname \"*backup*\" -perm -0002 2>/dev/null || true"
if find / -maxdepth 7 -type f -iname "*backup*" -perm -0002 2>/dev/null | grep -q .; then
    flag_red "World-writable backup scripts; high tampering risk → [P1-BK-PERMS]"
fi

runcheck "Permissions of common backup scripts [P1-BK-PERMS]" \
"for f in /etc/backup* /usr/local/bin/backup* /opt/backup* /root/backup* 2>/dev/null; do [ -f \"\$f\" ] && stat -c \"%a %U:%G %n\" \"\$f\"; done"

###############################################################################
# BACKUP USER/GROUP ENUMERATION — P1-BK-USERS
###############################################################################

runcheck "Users with 'backup' in name [P1-BK-USERS]" \
"grep -i \"backup\" /etc/passwd || true"
if grep -i "backup" /etc/passwd >/dev/null 2>&1; then
    flag_orange "Backup-related users exist; verify shell and permissions → [P1-BK-USERS]"
fi

runcheck "Groups with 'backup' in name [P1-BK-USERS]" \
"grep -i \"backup\" /etc/group || true"

runcheck "Check for 'backup' user [P1-BK-USERS]" \
"id backup 2>/dev/null || true"

###############################################################################
# BACKUP SERVICE EXPOSURE — P1-BK-SVCEXPOSE
###############################################################################

runcheck "rsync daemon exposure (873) [P1-BK-SVCEXPOSE]" \
"ss -tulnp | grep -E ':873' || true"
if ss -tulnp | grep -E ':873' >/dev/null 2>&1; then
    flag_orange "rsync daemon listening; verify network exposure and ACLs → [P1-BK-SVCEXPOSE]"
fi

runcheck "NFS exposure (2049) [P1-BK-SVCEXPOSE]" \
"ss -tulnp | grep -E ':2049' || true"
if ss -tulnp | grep -E ':2049' >/dev/null 2>&1; then
    flag_red "NFS service listening; high risk if exposed externally → [P1-BK-SVCEXPOSE]"
fi

runcheck "SMB exposure (445) [P1-BK-SVCEXPOSE]" \
"ss -tulnp | grep -E ':445' || true"
if ss -tulnp | grep -E ':445' >/dev/null 2>&1; then
    flag_red "SMB service listening; high risk if exposed externally → [P1-BK-SVCEXPOSE]"
fi

runcheck "SSH exposure (22) [P1-BK-SVCEXPOSE]" \
"ss -tulnp | grep -E ':22' || true"
if ss -tulnp | grep -E ':22' >/dev/null 2>&1; then
    flag_green "SSH listening as expected for admin access → [P1-BK-SVCEXPOSE]"
else
    flag_orange "SSH not listening; remote admin may be impaired → [P1-BK-SVCEXPOSE]"
fi

###############################################################################
# BACKUP SIZE + TIMESTAMP META — P1-BK-META
###############################################################################

runcheck "Recent tar archives with timestamps [P1-BK-META]" \
"find / -type f -name \"*.tar*\" -printf \"%TY-%Tm-%Td %TH:%TM %p\n\" 2>/dev/null || true"

runcheck "LVM snapshot sizes [P1-BK-META]" \
"lvs --options lv_name,lv_size,lv_attr | grep 's' || true"

runcheck "ZFS snapshot sizes [P1-BK-META]" \
"zfs list -t snapshot || true"

###############################################################################
# COMPROMISE-AWARE CHECKS — P1-BK-COMP
###############################################################################

runcheck "Backup scripts in /tmp or /dev/shm [P1-BK-COMP]" \
"find /tmp /dev/shm -type f -iname \"*backup*\" 2>/dev/null || true"
if find /tmp /dev/shm -type f -iname "*backup*" 2>/dev/null | grep -q .; then
    flag_red "Backup-like scripts in /tmp or /dev/shm; likely attacker artifacts → [P1-BK-COMP]"
fi

runcheck "Backup destinations in world-writable paths [P1-BK-COMP]" \
"find / -maxdepth 5 -type d -perm -0002 -iname \"backup*\" 2>/dev/null || true"
if find / -maxdepth 5 -type d -perm -0002 -iname "backup*" 2>/dev/null | grep -q .; then
    flag_red "Backup destinations in world-writable paths; high tampering risk → [P1-BK-COMP]"
fi

runcheck "Exfiltration-like rsync commands [P1-BK-COMP]" \
"grep -R \"rsync .*@\" /etc /usr/local /opt /root /home 2>/dev/null || true"
if grep -R "rsync .*@" /etc /usr/local /opt /root /home 2>/dev/null | grep -q .; then
    flag_red "Exfiltration-like rsync commands detected; investigate immediately → [P1-BK-COMP]"
fi

###############################################################################
# END
###############################################################################

log "BACKUP ROLE PACK SCRIPT COMPLETE"
echo "" >> "$OUTFILE"
