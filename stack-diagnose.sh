#!/usr/bin/env bash
# stack-diagnose.sh - Debian/Ubuntu server diagnostics (read-only)
# Copyright (c) 2026, Mnheia <mnheia@gmail.com>
#
# This module is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License, version 3.
# See the LICENSE and COPYRIGHT files in the repository for details.
#
# Auto-detects services including Apache, WordPress/WooCommerce, Nextcloud, mail, MariaDB, Redis and Docker.
#
# Safe-by-default:
# - No config writes
# - No service restarts
# - Uses lightweight commands + tail/journal snippets
#
# Optional env:
#   DOMAIN=example.com          # for DNS/MX/TLS SNI checks where applicable
#   TEST_EMAIL=ops@example.com  # postfix routing probe (sendmail -bv) - no mail sent
#   REDIS_AUTH=secret           # if redis-cli requires AUTH
#   REDIS_SOCKET=/run/redis/redis-server.sock  # optional Redis Unix socket
#   MYSQL_USER=root             # mysql client user (defaults to root)
#   MYSQL_PWD=...               # mysql client password (optional)
#   MYSQL_HOST=localhost
#   MYSQL_PORT=3306
#   WP_ROOT=/path/to/wordpress    # optional extra WordPress root
#   NC_ROOT=/path/to/nextcloud    # optional extra Nextcloud root
#   NEXTCLOUD_ROOT=/path/to/nextcloud  # legacy alias of NC_ROOT
#   SUITECRM_ROOT=/path/to/suitecrm    # optional custom SuiteCRM root
#   BACKUP_PATHS="/path/to/backups" # optional list of expected backup directories
#   BACKUP_MAX_AGE_HOURS=36       # used only when BACKUP_PATHS specified
#
# Usage:
#   sudo bash stack_diag.sh
#   sudo DOMAIN=example.com bash stack_diag.sh
#
set -Eeuo pipefail
umask 077

VERSION="2026-11-22-review3.2"
MODE="full"

# --------- globals ----------
HOST="$(hostname -f 2>/dev/null || hostname)"
TS="$(date +'%Y%m%d_%H%M%S')"
OUT="/tmp/stack_diag_${HOST}_${TS}.log"
TMPDIR="$(mktemp -d -t stack_diag.XXXXXX)"
WP_CACHE_DIR=""
cleanup() {
  [[ -z "$WP_CACHE_DIR" ]] || rm -rf -- "$WP_CACHE_DIR"
  rm -rf -- "$TMPDIR"
}
trap cleanup EXIT

DOMAIN="${DOMAIN:-}"
TEST_EMAIL="${TEST_EMAIL:-}"
REDIS_AUTH="${REDIS_AUTH:-${REDISCLI_AUTH:-}}"
REDIS_SOCKET="${REDIS_SOCKET:-}"

MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PWD="${MYSQL_PWD:-}"
MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_SOCKET="${MYSQL_SOCKET:-}"
WP_ROOT="${WP_ROOT:-}"
NC_ROOT="${NC_ROOT:-${NEXTCLOUD_ROOT:-}}"
SUITECRM_ROOT="${SUITECRM_ROOT:-}"
BACKUP_PATHS="${BACKUP_PATHS:-}"
BACKUP_MAX_AGE_HOURS="${BACKUP_MAX_AGE_HOURS:-36}"
WP_TIMEOUT=20
BACKUP_ASSESSED=0
REDIS_ACTIVE_ENDPOINT=""
REDIS_ACTIVE_POLICY=""
# App discovery is deliberately shallow: do not recurse through uploads/data trees.
WEB_ROOTS=()
WP_ROOTS=()
NC_ROOTS=()
# Explicit TCP only if a non-localhost host is supplied. Otherwise try socket.


# soft limits
JOURNAL_LINES=200
LOG_TAIL_LINES=200
CMD_TIMEOUT=8

usage() {
  cat <<'HELP'
Usage: stack-diagnose.sh [--full|--quick|--storage-write|--mysqltuner|--help]
  --full           Complete read-only report (default, backward compatible).
  --quick          Essential health checks only.
  --storage-write  60-second read-only /sys/block disk write sampling.
  --mysqltuner     Run only local MySQLTuner (if installed); read-only,
                   up to 120s; not included in routine reports.
  --help           Print this help.

Environment: DOMAIN, TEST_EMAIL, REDIS_AUTH, REDIS_SOCKET, MYSQL_USER,
             MYSQL_PWD, MYSQL_HOST, MYSQL_PORT, MYSQL_SOCKET,
             WP_ROOT, NC_ROOT, NEXTCLOUD_ROOT, SUITECRM_ROOT,
             BACKUP_PATHS, BACKUP_MAX_AGE_HOURS.
No services are restarted and no configurations are explicitly modified.
Full mode can invoke read-only WP-CLI commands; WordPress bootstrap/plugin hooks
may still update application caches/transients. Run on a staging site first if needed.
Reports are created with mode 0600 under /tmp.
HELP
}

if (( $# > 1 )); then usage >&2; exit 2; fi
case "${1:---full}" in
  --full) MODE="full" ;;
  --quick) MODE="quick" ;;
  --storage-write) MODE="storage-write" ;;
  --mysqltuner) MODE="mysqltuner" ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

# --------- helpers ----------
redact() {
  sed -E \
    -e 's/(password|passwd|pwd|secret|token|apikey|api_key|access_key|private_key|client_secret|MYSQL_PWD|REDIS_AUTH)([[:space:]]*[:=][[:space:]]*)[^[:space:]"'\'';]+/\1\2[REDACTED]/Ig' \
    -e 's#(sshpass[[:space:]]+-p[[:space:]]+)([^[:space:]]+)#\1[REDACTED]#Ig' \
    -e 's#(sshpass[[:space:]]+-f[[:space:]]+)([^[:space:]]+)#\1[REDACTED_PATH]#Ig' \
    -e 's#(://[^:/[:space:]]+:)([^@/[:space:]]+)(@)#\1[REDACTED]\3#g' \
    -e 's#(Authorization:[[:space:]]*)(Bearer|Basic)[[:space:]]+[^[:space:]]+#\1\2 [REDACTED]#Ig' \
    -e 's#([A-Za-z0-9._%+-]+):([^[:space:]@/]+)@#\1:[REDACTED]@#g'
}

say() { printf '%s\n' "$*" | redact | tee -a "$OUT" >/dev/null; }
hr()  { say "--------------------------------------------------------------------------------"; }
sec() { hr; say "# $*"; hr; }

has() { command -v "$1" >/dev/null 2>&1; }

run() {
  # Diagnostic runner: preserve command status even with output redaction.
  # This intentionally returns success to allow the full report to continue.
  local label="$1" rc=0; shift
  local capture="$TMPDIR/command-output"
  local seconds="${RUN_TIMEOUT:-$CMD_TIMEOUT}"
  say ">> ${label}"
  : > "$capture"
  if has timeout; then
    timeout "${seconds}"s "$@" >"$capture" 2>&1 || rc=$?
  else
    "$@" >"$capture" 2>&1 || rc=$?
  fi
  # Limit report volume from unexpectedly verbose commands.
  head -c 262144 "$capture" | sed 's/\r$//' | redact >> "$OUT" || true
  if (( $(wc -c < "$capture") > 262144 )); then
    say "[TRUNCATED] Command output exceeded 256 KiB"
  fi
  if (( rc == 124 || rc == 137 )); then
    say "[CHECK-TIMEOUT] ${label}: timeout after ${seconds}s (exit ${rc})"
  elif (( rc != 0 )); then
    say "[CHECK-FAILED] ${label}: exit ${rc}"
  fi
  say ""
}

file_tail() {
  local f="$1"
  if [[ -f "$f" ]]; then
    say ">> tail -n ${LOG_TAIL_LINES} $f"
    tail -n "${LOG_TAIL_LINES}" "$f" 2>&1 | redact | tee -a "$OUT" >/dev/null || true
    say ""
  fi
}

journal_unit() {
  local unit="$1"
  if has journalctl; then
    say ">> journalctl -b -u ${unit} -n ${JOURNAL_LINES} --no-pager"
    journalctl -b -u "$unit" -n "${JOURNAL_LINES}" --no-pager 2>&1 | redact | tee -a "$OUT" >/dev/null || true
    say ""
  fi
}

risk() { say "[RISK] $*"; }
warn() { say "[WARN] $*"; }
perf() { say "[PERF] $*"; }
tune() { say "[TUNE] $*"; }
fail() { say "[FAIL] $*"; }
info() { say "[INFO] $*"; }

# --------- detection ----------
systemd_unit_exists() {
  local unit="$1"
  systemctl list-unit-files "$unit" --no-legend 2>/dev/null | awk -v unit="$unit" '$1 == unit { found=1 } END { exit !found }'
}

systemd_unit_active() {
  local unit="$1"
  systemctl is-active "$unit" >/dev/null 2>&1
}

port_listen_contains() {
  # port_listen_contains 443 or 127.0.0.1:9200 substring match on ss output
  local needle="$1"
  ss -ltnp 2>/dev/null | grep -Fq "$needle"
}

detect() {
  # returns 0 if "present"
  local svc="$1"
  case "$svc" in
    nginx)        systemd_unit_exists nginx.service || has nginx ;;
    apache)       systemd_unit_exists apache2.service || has apache2ctl ;;
    postfix)      systemd_unit_exists postfix.service || has postconf ;;
    mysql)        systemd_unit_exists mysql.service || systemd_unit_exists mariadb.service || has mysql || has mariadb ;;
    redis)        systemd_unit_exists redis-server.service || systemd_unit_exists redis.service || has redis-cli ;;
    nextcloud)    (( ${#NC_ROOTS[@]} > 0 )) ;;
    wordpress)    (( ${#WP_ROOTS[@]} > 0 )) ;;
    zimbra)       [[ -x /opt/zimbra/bin/zmcontrol || -d /opt/zimbra ]] ;;
    elasticsearch) systemd_unit_exists elasticsearch.service || has elasticsearch || port_listen_contains ":9200" ;;
    logstash)     systemd_unit_exists logstash.service || has logstash ;;
    zabbix_agent) systemd_unit_exists zabbix-agent.service || systemd_unit_exists zabbix-agent2.service || has zabbix_agentd ;;
    zabbix_srv)   systemd_unit_exists zabbix-server.service || systemd_unit_exists zabbix-proxy.service ;;
    django)       systemctl list-units --type=service --all --no-legend 2>/dev/null | grep -Eiq '(gunicorn|uwsgi|daphne|uvicorn)' ;;
    suitecrm)     [[ -n "$SUITECRM_ROOT" && -d "$SUITECRM_ROOT" ]] || [[ -d /var/www/suitecrm || -d /var/www/html/suitecrm || -d /srv/suitecrm ]] ;;
    *) return 1 ;;
  esac
}

# --------- application discovery (shallow, bounded, no recursive scans) ----------
add_unique_dir() {
  local dir="$1" item
  [[ -n "$dir" && -d "$dir" ]] || return 0
  for item in "${WEB_ROOTS[@]}"; do [[ "$item" == "$dir" ]] && return 0; done
  WEB_ROOTS+=("$dir")
}

discover_applications() {
  local conf line dir item
  # Only enabled Apache vhosts; DocumentRoot may be quoted.
  for conf in /etc/apache2/sites-enabled/*.conf; do
    [[ -f "$conf" ]] || continue
    while IFS= read -r line; do
      line="${line#*DocumentRoot}"
      line="${line#\"}"; line="${line%%\"*}"
      line="${line%%[[:space:]]*}"
      [[ "$line" == /* ]] && add_unique_dir "$line"
    done < <(sed -nE '/^[[:space:]]*DocumentRoot[[:space:]]/s/^[[:space:]]*DocumentRoot[[:space:]]+//p' "$conf" 2>/dev/null)
  done
  # Common locations plus explicitly supplied paths. Globs expand one level only.
  for dir in "$WP_ROOT" "$NC_ROOT" \
      /srv/www/vhost/*/public_html /srv/www/vhost/*/public_html/* \
      /srv/www/vhost/oblak.* /var/www/nextcloud /var/www/html/nextcloud \
      /var/www/html /var/www/wordpress /srv/nextcloud; do
    add_unique_dir "$dir"
  done
  for dir in "${WEB_ROOTS[@]}"; do
    if [[ -f "$dir/wp-load.php" && -f "$dir/wp-includes/version.php" ]]; then
      local found=0
      for item in "${WP_ROOTS[@]}"; do [[ "$item" == "$dir" ]] && found=1; done
      (( found == 1 )) || WP_ROOTS+=("$dir")
    fi
    if [[ -f "$dir/occ" && -f "$dir/version.php" ]]; then
      local found=0
      for item in "${NC_ROOTS[@]}"; do [[ "$item" == "$dir" ]] && found=1; done
      (( found == 1 )) || NC_ROOTS+=("$dir")
    fi
  done
}

# --------- core system checks ----------
sys_overview() {
  sec "Meta"
  say "stack_diag version: ${VERSION}"
  say "host: ${HOST}"
  say "timestamp: ${TS}"
  say "output: ${OUT}"
  say "domain: ${DOMAIN:-<unset>}"
  say ""

  sec "OS + Kernel"
  run "uname -a" uname -a
  if [[ -r /etc/os-release ]]; then
    run "cat /etc/os-release" bash -lc "cat /etc/os-release"
  fi
  run "uptime" uptime
  run "who -b" who -b || true
  if has last; then
    run "last reboot (last -x | head)" bash -lc "last -x | head -n 10"
  else
    info "last unavailable; skipped reboot history."
  fi

  sec "CPU + Memory"
  run "lscpu (summary)" bash -lc "lscpu | egrep -i 'model name|socket|cpu\\(s\\)|thread|core|mhz|virtualization' || true"
  run "free -h" free -h
  run "vmstat 1 5" bash -lc "vmstat 1 5 || true"
  run "top (snapshot)" bash -lc "top -b -n 1 | head -n 25 || true"

  sec "Storage"
  run "df -hT" df -hT
  run "lsblk -f" lsblk -f || true
  run "mount (interesting)" bash -lc "mount | egrep -i 'ext4|xfs|btrfs|zfs|nfs|cifs|fuse' || true"
  if [[ "$MODE" == "full" ]]; then
    run "largest dirs (/var /home /opt) quick" bash -lc "du -x -h -d 1 /var /home /opt 2>/dev/null | sort -h | tail -n 30 || true"
  fi

  sec "Network"
  run "ip -br a" ip -br a
  run "ip r" ip r
  run "resolvectl status (if systemd-resolved)" bash -lc "resolvectl status 2>/dev/null || true"
  run "ss -ltnp" ss -ltnp || true
  run "ss -lunp" ss -lunp || true

  sec "Time"
  run "timedatectl" timedatectl || true
  if has chronyc; then
    run "chronyc tracking" chronyc tracking || true
    run "chronyc sources -v" chronyc sources -v || true
  elif has ntpq; then
    run "ntpq -p" ntpq -p || true
  else
    warn "No chronyc/ntpq detected; NTP health not verified."
  fi

  sec "Security quick scan"
  run "failed logins (lastb head)" bash -lc "lastb 2>/dev/null | head -n 20 || true"
  run "sudoers (who can sudo) - best effort" bash -lc "getent group sudo 2>/dev/null || true; getent group wheel 2>/dev/null || true"
  run "ssh config highlights" bash -lc "sshd -T 2>/dev/null | egrep -i 'passwordauthentication|permitrootlogin|pubkeyauthentication|challenge' || true"
  run "firewall (nft/iptables) summary" bash -lc "nft list ruleset 2>/dev/null | head -n 120 || iptables -S 2>/dev/null | head -n 120 || true"
  run "fail2ban status" bash -lc "fail2ban-client status 2>/dev/null || true"
  run "AppArmor status" bash -lc "aa-status 2>/dev/null || true"
  run "SELinux status" bash -lc "getenforce 2>/dev/null || true"

  sec "Systemd health"
  run "systemctl --failed" systemctl --failed || true
  run "boot errors (journalctl -p 0..3 -b)" bash -lc "journalctl -p 0..3 -b --no-pager | tail -n 200 || true"
}

# --------- TLS / cert checks ----------
check_cert_file() {
  local cert="$1"
  if has openssl && [[ -r "$cert" ]]; then
    say ">> openssl x509 -enddate -subject -issuer -in $cert"
    openssl x509 -enddate -subject -issuer -in "$cert" 2>&1 | redact | tee -a "$OUT" >/dev/null || true
    say ""
  fi
}

check_domain_tls() {
  [[ -n "$DOMAIN" ]] || return 0
  has openssl || return 0
  sec "DNS/TLS checks for DOMAIN=$DOMAIN"

  if has dig; then
    run "dig +short A ${DOMAIN}" dig +short A "$DOMAIN"
    run "dig +short AAAA ${DOMAIN}" dig +short AAAA "$DOMAIN"
    run "dig +short MX ${DOMAIN}" dig +short MX "$DOMAIN"
  elif has host; then
    run "host ${DOMAIN}" host "$DOMAIN"
  else
    warn "No dig/host available for DNS checks."
  fi

  # TLS probe (SNI)
  say ">> openssl s_client SNI probe :443 (best effort)"
  (echo | timeout 8s openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:443" 2>/dev/null | openssl x509 -noout -subject -issuer -dates) \
    2>&1 | redact | tee -a "$OUT" >/dev/null || true
  say ""
}

# --------- service modules ----------
mod_nginx() {
  sec "Nginx"
  run "systemctl status nginx (summary)" bash -lc "systemctl status nginx --no-pager -l | head -n 80 || true"
  if has nginx; then
    run "nginx -V" nginx -V
    run "nginx -t" nginx -t
    run "nginx effective config snippets (paths)" bash -lc "nginx -T 2>/dev/null | head -n 240 || true"
  else
    warn "nginx binary not found; relying on systemd/logs only."
  fi

  # common logs
  file_tail /var/log/nginx/error.log
  file_tail /var/log/nginx/access.log

  # TLS cert common paths
  for c in /etc/ssl/certs/*.pem /etc/letsencrypt/live/*/fullchain.pem; do
    [[ -e "$c" ]] || continue
    check_cert_file "$c"
    break
  done

  journal_unit nginx.service
}

mod_apache() {
  sec "Apache"
  run "systemctl status apache2 (summary)" bash -lc "systemctl status apache2 --no-pager -l | head -n 80 || true"
  if has apache2ctl; then
    run "apache2ctl -V" apache2ctl -V
    run "apache2ctl -M" apache2ctl -M
    run "apache2ctl -S" apache2ctl -S
    run "apache2ctl configtest" apache2ctl configtest
  fi
  file_tail /var/log/apache2/error.log
  file_tail /var/log/apache2/access.log
  journal_unit apache2.service
  check_php_runtime
}

check_php_runtime() {
  has php || return 0
  sec "PHP CLI / Apache OPcache configuration (not live cache usage)"
  local version_id="" version_out="$TMPDIR/php-version" f effective="" invalid=""
  # -n bypasses local ini files so the version probe works even with a broken extension directive.
  version_id="$(timeout 5 php -n -r 'echo PHP_VERSION_ID;' 2>/dev/null || true)"
  if [[ "$version_id" =~ ^[0-9]+$ ]]; then
    info "PHP CLI version ID (no php.ini): $version_id"
  fi
  timeout 5 php -v >"$version_out" 2>&1 || true
  if grep -Eiq 'Failed loading Zend extension|Unable to load dynamic library.*opcache' "$version_out"; then
    warn "PHP CLI reports an OPcache startup/loading error; inspect PHP version and active ini directives."
    grep -Ei 'Failed loading Zend extension|Unable to load dynamic library.*opcache' "$version_out" | head -n 3 | redact >> "$OUT" || true
  fi
  run "PHP CLI version and loaded extensions" php -v
  run "PHP ini scan path" php --ini
  run "Effective CLI OPcache settings" php -r 'foreach (["opcache.enable","opcache.enable_cli","opcache.memory_consumption","opcache.interned_strings_buffer","opcache.max_accelerated_files"] as $k) { echo $k,"=",ini_get($k),PHP_EOL; }'
  for f in /etc/php/*/apache2/conf.d/*opcache*.ini /etc/php/*/cli/conf.d/*opcache*.ini; do
    [[ -e "$f" ]] || continue
    say "OPcache ini: $f -> $(readlink -f "$f" 2>/dev/null || echo unknown)"
  done
  # Avoid counting Apache/CLI symlinks twice; inspect the canonical module config.
  if [[ "$version_id" =~ ^[0-9]+$ ]] && (( version_id >= 80500 )); then
    local active_php_series
    active_php_series="$((version_id / 10000)).$(( (version_id / 100) % 100 ))"
    for f in /etc/php/"$active_php_series"/mods-available/opcache.ini; do
      [[ -r "$f" ]] || continue
      if grep -Eiq '^[[:space:]]*zend_extension[[:space:]]*=[[:space:]]*"?opcache([.]so)?"?([[:space:]]*(;.*)?)?$' "$f"; then
        warn "PHP 8.5+ uses built-in OPcache; obsolete zend_extension=opcache.so directive present in $f."
      fi
    done
  fi
  local errors
  errors="$(journalctl -b -u apache2.service --no-pager 2>/dev/null | grep -Ei 'Failed loading Zend extension|opcache.*(fatal|error)' | tail -n 6 || true)"
  if [[ -n "$errors" ]]; then
    warn "Current-boot Apache OPcache extension loading errors were logged."
    printf '%s\n' "$errors" | redact >> "$OUT"
  else
    info "No matching current-boot Apache OPcache loading failures. Apache live OPcache usage not verified."
  fi
}

mod_postfix() {
  sec "Postfix"
  run "systemctl status postfix (summary)" bash -lc "systemctl status postfix --no-pager -l | head -n 80 || true"
  if has postconf; then
    run "postconf -n (non-defaults)" bash -lc "postconf -n 2>/dev/null | head -n 300 || true"
    run "postqueue -p (queue summary)" bash -lc "postqueue -p 2>/dev/null | head -n 200 || true"
    if [[ -n "$TEST_EMAIL" ]] && has sendmail; then
      run "sendmail -bv ${TEST_EMAIL} (routing probe; no mail sent)" sendmail -bv "$TEST_EMAIL"
    fi
  fi
  check_postfix_queue
  file_tail /var/log/mail.log
  file_tail /var/log/mail.err
  journal_unit postfix.service
}

# Postfix JSON queue inspection: counts only; never print envelope addresses.
check_postfix_queue() {
  has postqueue || return 0
  sec "Postfix delivery queue health"
  local qfile="$TMPDIR/postfix-queue.jsonl" rc=0 counts deferred hold total
  timeout 8 postqueue -j > "$qfile" 2>/dev/null || rc=$?
  if (( rc != 0 )); then
    info "postqueue -j unavailable; queue count not assessed (see postqueue -p output)."
    return 0
  fi
  if ! has python3; then
    info "python3 unavailable; JSON queue count not assessed."
    return 0
  fi
  counts="$(python3 - "$qfile" <<'PYPOST'
import json,sys
from collections import Counter
c=Counter()
for line in open(sys.argv[1],encoding='utf-8',errors='replace'):
    if line.strip():
        try: c[json.loads(line).get('queue_name','unknown')]+=1
        except ValueError: pass
print(sum(c.values()),c['deferred'],c['hold'])
PYPOST
)" || { warn "Postfix queue JSON parsing failed"; return 0; }
  read -r total deferred hold <<< "$counts"
  info "Postfix messages: total=$total deferred=$deferred hold=$hold"
  if (( deferred > 0 )); then
    warn "Postfix has $deferred deferred message(s). Inspect delivery reasons; transactional mail may be delayed."
  fi
  if (( hold > 0 )); then
    warn "Postfix has $hold held message(s)."
  fi
}

# Choose the local Unix socket by default; TCP is used only when
# MYSQL_HOST names a remote host or an explicit loopback IP.
MYSQL_CLIENT=""
MYSQL_ARGS=()
mysql_prepare() {
  if has mysql; then MYSQL_CLIENT="mysql"
  elif has mariadb; then MYSQL_CLIENT="mariadb"
  else return 1; fi
  MYSQL_ARGS=(-u "$MYSQL_USER" --connect-timeout=5 --batch --skip-column-names)
  if [[ "$MYSQL_HOST" == "localhost" || -z "$MYSQL_HOST" ]]; then
    MYSQL_ARGS+=(--protocol=socket)
    [[ -z "$MYSQL_SOCKET" ]] || MYSQL_ARGS+=(--socket="$MYSQL_SOCKET")
    info "Database transport: Unix socket (local)."
  else
    MYSQL_ARGS+=(--protocol=tcp -h "$MYSQL_HOST" -P "$MYSQL_PORT")
    info "Database transport: TCP to explicit MYSQL_HOST."
  fi
}
mysql_run_query() {
  local label="$1" query="$2"
  # MYSQL_PWD is passed as environment, never as a command-line argument.
  if [[ -n "$MYSQL_PWD" ]]; then
    MYSQL_PWD="$MYSQL_PWD" run "$label" "$MYSQL_CLIENT" "${MYSQL_ARGS[@]}" -e "$query"
  else
    run "$label" "$MYSQL_CLIENT" "${MYSQL_ARGS[@]}" -e "$query"
  fi
}


# Aggregate counters; one short read-only query. Avoid a tuning warning based
# solely on a disk-temp ratio (TEXT/BLOB and other queries can require disk).
mysql_temp_summary() {
  local f="$TMPDIR/mysql-temp-summary" uptime total disk
  local q="SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Created_tmp_tables','Created_tmp_disk_tables');"
  if [[ -n "$MYSQL_PWD" ]]; then
    MYSQL_PWD="$MYSQL_PWD" timeout 5 "$MYSQL_CLIENT" "${MYSQL_ARGS[@]}" -e "$q" >"$f" 2>/dev/null || { info "Temporary-table ratio unavailable."; return 0; }
  else
    timeout 5 "$MYSQL_CLIENT" "${MYSQL_ARGS[@]}" -e "$q" >"$f" 2>/dev/null || { info "Temporary-table ratio unavailable."; return 0; }
  fi
  uptime="$(awk '$1=="Uptime" {print $2}' "$f")"
  total="$(awk '$1=="Created_tmp_tables" {print $2}' "$f")"
  disk="$(awk '$1=="Created_tmp_disk_tables" {print $2}' "$f")"
  if [[ "$uptime" =~ ^[0-9]+$ && "$total" =~ ^[0-9]+$ && "$disk" =~ ^[0-9]+$ && "$total" -gt 0 ]]; then
    say "Temporary tables since MariaDB restart: $total total, $disk on disk ($(awk -v d="$disk" -v t="$total" 'BEGIN {printf "%.1f",100*d/t}')%). Uptime: ${uptime}s."
    if (( uptime < 86400 )); then
      info "Temporary-table ratios are preliminary: database uptime <24h; retest after representative load."
    else
      info "Disk temp tables may be necessary due to query shape/data types; raising limits is not always beneficial."
    fi
  else
    info "Temporary-table ratio not calculated (insufficient counters)."
  fi
}

# Optional, separate from the full health report. Uses the locally installed
# MySQLTuner package, never downloads or self-updates software.
mod_mysqltuner() {
  sec "MySQLTuner (optional, separately invoked)"
  if ! has mysqltuner; then
    info "MySQLTuner is not installed; Debian/Ubuntu: apt install mysqltuner (not performed by this script)."
    return 0
  fi
  if [[ -n "$MYSQL_PWD" || "$MYSQL_HOST" != localhost || -n "$MYSQL_SOCKET" || "$MYSQL_USER" != root ]]; then
    warn "MySQLTuner integration supports only local root socket defaults; no credentials or custom hosts are forwarded. Run manually with a protected option file for other configurations."
    return 0
  fi
  info "Runs read-only diagnostics against local database; may execute significant metadata queries and take up to 120 seconds."
  info "Review recommendations critically; at least 24–48h of normal database uptime is advised."
  RUN_TIMEOUT=120 run "mysqltuner --nocolor --nondedicated --skippassword" \
    mysqltuner --nocolor --nondedicated --skippassword
}

mod_mysql() {
  sec "MySQL/MariaDB"
  run "systemctl status mysql/mariadb (summary)" bash -lc "systemctl status mysql mariadb --no-pager -l | head -n 120 || true"
  if mysql_prepare; then
    run "mysql/mariadb --version" "$MYSQL_CLIENT" --version
    # Authentication and socket connectivity: only one attempt on failure.
    local probe_rc=0 probe="$TMPDIR/mysql-preflight"
    if [[ -n "$MYSQL_PWD" ]]; then
      MYSQL_PWD="$MYSQL_PWD" timeout 5 "$MYSQL_CLIENT" "${MYSQL_ARGS[@]}" -e 'SELECT 1;' >"$probe" 2>&1 || probe_rc=$?
    else
      timeout 5 "$MYSQL_CLIENT" "${MYSQL_ARGS[@]}" -e 'SELECT 1;' >"$probe" 2>&1 || probe_rc=$?
    fi
    if (( probe_rc != 0 )); then
      warn "Database probe failed (exit ${probe_rc}); skipping repeated SQL queries to avoid generating authentication errors."
      # Print sanitized diagnostic error without exposing credentials.
      head -n 4 "$probe" | redact >> "$OUT" || true
    else
      mysql_run_query "database version" 'SELECT @@version, @@version_comment;'
      mysql_run_query "uptime" "SHOW GLOBAL STATUS LIKE 'Uptime';"
      mysql_run_query "threads_connected" "SHOW GLOBAL STATUS LIKE 'Threads_connected';"
      mysql_run_query "max_used_connections" "SHOW GLOBAL STATUS LIKE 'Max_used_connections';"
      mysql_run_query "buffer pool and limits" "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('innodb_buffer_pool_size','innodb_log_file_size','max_connections','tmp_table_size','max_heap_table_size','innodb_buffer_pool_size_max');"
      mysql_run_query "InnoDB working set / buffer hits" "SHOW GLOBAL STATUS WHERE Variable_name IN ('Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests','Innodb_buffer_pool_pages_data','Innodb_buffer_pool_pages_total','Created_tmp_disk_tables','Created_tmp_tables');"
      mysql_temp_summary
      mysql_run_query "top 10 tables by size" 'SELECT table_schema, table_name, ROUND((data_length+index_length)/1024/1024,1) AS mb FROM information_schema.tables ORDER BY (data_length+index_length) DESC LIMIT 10;'
    fi
  else
    warn "Neither mysql nor mariadb client found."
  fi
  file_tail /var/log/mysql/error.log
  file_tail /var/log/mariadb/mariadb.log
  journal_unit mysql.service
  journal_unit mariadb.service
}

mod_redis() {
  sec "Redis"
  run "systemctl status redis (summary)" bash -lc "systemctl status redis redis-server --no-pager -l | head -n 120 || true"
  if has redis-cli; then
    local -a redis_args=(--no-auth-warning)
    local sock="${REDIS_SOCKET}"
    if [[ -z "$sock" ]]; then
      if [[ -S /run/redis/redis-server.sock ]]; then
        sock=/run/redis/redis-server.sock
      elif [[ -S /var/run/redis/redis-server.sock ]]; then
        sock=/var/run/redis/redis-server.sock
      fi
    fi
    if [[ -n "$sock" ]]; then
      if [[ ! -S "$sock" ]]; then
        warn "Configured Redis Unix socket is absent: $sock; skipping Redis connection probes."
        file_tail /var/log/redis/redis-server.log
        journal_unit redis-server.service
        journal_unit redis.service
        return 0
      fi
      redis_args+=(-s "$sock")
      REDIS_ACTIVE_ENDPOINT="unix:$(readlink -m "$sock" 2>/dev/null || printf '%s' "$sock")"
      info "Redis transport: Unix socket $sock"
    else
      redis_args+=(-h 127.0.0.1 -p 6379)
      REDIS_ACTIVE_ENDPOINT="tcp:127.0.0.1:6379"
      info "Redis transport: TCP 127.0.0.1:6379 (no Unix socket detected)."
    fi
    # The credential is inherited by redis-cli through environment only.
    # The password must not be inserted into shell strings or argv.
    if [[ -n "$REDIS_AUTH" ]]; then
      export REDISCLI_AUTH="$REDIS_AUTH"
    fi
    run "redis-cli PING" redis-cli "${redis_args[@]}" PING
    REDIS_ACTIVE_POLICY="$(timeout 5 redis-cli "${redis_args[@]}" --raw CONFIG GET maxmemory-policy 2>/dev/null | tail -n 1 || true)"
    run "redis-cli INFO (filtered)" bash -o pipefail -c \
      'redis-cli "$@" INFO | grep -Ei "^(redis_version|uptime_in_seconds|connected_clients|used_memory_human|maxmemory_human|maxmemory_policy|evicted_keys|keyspace_hits|keyspace_misses):"' \
      _ "${redis_args[@]}"
    unset REDISCLI_AUTH
  else
    warn "redis-cli not found."
  fi
  file_tail /var/log/redis/redis-server.log
  journal_unit redis-server.service
  journal_unit redis.service
}

find_nextcloud_root() {
  (( ${#NC_ROOTS[@]} > 0 )) || return 1
  printf '%s\n' "${NC_ROOTS[0]}"
}

nextcloud_recent_log_summary() {
  local log="$1"
  [[ -r "$log" ]] || return 0
  if ! has python3; then
    info "Nextcloud structured log summary unavailable (python3 absent): $log"
    return 0
  fi
  say ">> Nextcloud recent log counts ($log; bounded last 2 MiB, messages omitted)"
  timeout 8 python3 - "$log" <<'PYNEXT' | redact >> "$OUT"
import collections, datetime, json, os, sys
p=sys.argv[1]
now=datetime.datetime.now(datetime.timezone.utc)
counts=collections.Counter()
read=0
try:
    with open(p,'rb') as f:
        f.seek(0,os.SEEK_END)
        end=f.tell()
        f.seek(max(0,end-2*1024*1024))
        data=f.read().splitlines()[-300:]
    for raw in data:
        try:
            v=json.loads(raw)
            stamp=v.get('time','')
            ts=datetime.datetime.fromisoformat(stamp.replace('Z','+00:00'))
            if ts.tzinfo is None: ts=ts.replace(tzinfo=datetime.timezone.utc)
            hours=(now-ts).total_seconds()/3600
            if not (0<=hours<=168): continue
            level=int(v.get('level',0))
            if level >= 3:
                counts['7d']+=1
                if hours <= 24: counts['24h']+=1
        except (ValueError, TypeError, AttributeError, UnicodeError):
            continue
    print(f"Recent Nextcloud severity>=3: last 24h={counts['24h']}, last 7d={counts['7d']}; sample of up to 300 recent lines")
except (OSError, PermissionError) as e:
    print(f"Could not inspect Nextcloud log metadata: {type(e).__name__}")
PYNEXT
}

mod_nextcloud() {
  sec "Nextcloud"
  local root
  if ! root="$(find_nextcloud_root)"; then
    warn "Nextcloud detected by heuristics but occ not found in standard locations."
    return 0
  fi
  say "[INFO] Nextcloud root: $root"
  run "php -v" bash -lc "php -v 2>/dev/null | head -n 5 || true"
  run "occ status (read-only)" runuser -u www-data -- php "$root/occ" status
  run "occ config:system get trusted_domains" runuser -u www-data -- php "$root/occ" config:system:get trusted_domains
  run "occ maintenance:mode" runuser -u www-data -- php "$root/occ" maintenance:mode
  # Check effective cache classes without displaying the Redis credential array.
  run "occ memcache.local" runuser -u www-data -- php "$root/occ" config:system:get memcache.local
  run "occ memcache.locking" runuser -u www-data -- php "$root/occ" config:system:get memcache.locking
  run "occ memcache.distributed" runuser -u www-data -- php "$root/occ" config:system:get memcache.distributed
  # Compare Redis endpoint only; never retrieve the Nextcloud redis password.
  if [[ -n "$REDIS_ACTIVE_ENDPOINT" && -n "$REDIS_ACTIVE_POLICY" ]]; then
    local locking cfg_host cfg_port cfg_endpoint=""
    locking="$(timeout 8 runuser -u www-data -- php "$root/occ" config:system:get memcache.locking 2>/dev/null || true)"
    if [[ "$locking" == *Redis* ]]; then
      cfg_host="$(timeout 8 runuser -u www-data -- php "$root/occ" config:system:get redis host 2>/dev/null || true)"
      cfg_port="$(timeout 8 runuser -u www-data -- php "$root/occ" config:system:get redis port 2>/dev/null || true)"
      if [[ "$cfg_host" == /* ]]; then
        cfg_endpoint="unix:$(readlink -m "$cfg_host" 2>/dev/null || printf '%s' "$cfg_host")"
      elif [[ "$cfg_host" == localhost || "$cfg_host" == 127.0.0.1 ]]; then
        [[ "$cfg_port" =~ ^[0-9]+$ ]] || cfg_port=6379
        cfg_endpoint="tcp:127.0.0.1:$cfg_port"
      fi
      if [[ -n "$cfg_endpoint" && "$cfg_endpoint" == "$REDIS_ACTIVE_ENDPOINT" ]]; then
        info "Nextcloud file locking uses the Redis instance examined above (endpoint matched)."
        if [[ "$REDIS_ACTIVE_POLICY" != noeviction ]]; then
          warn "Nextcloud Redis file locking shares a Redis instance with eviction policy '$REDIS_ACTIVE_POLICY'; evictions could remove live lock keys. Review isolation/noeviction."
        fi
      else
        info "Nextcloud file locking uses Redis, but its endpoint was not confirmed as the Redis instance examined above; no eviction warning inferred."
      fi
    fi
  fi
  run "occ background jobs configuration" runuser -u www-data -- php "$root/occ" config:app:get core backgroundjobs_mode
  run "occ app:list (enabled only)" runuser -u www-data -- php "$root/occ" app:list --enabled

  # permissions sanity
  if [[ -f "$root/config/config.php" ]]; then
    run "config.php perms" bash -lc "ls -l '$root/config/config.php' && stat -c '%a %U:%G %n' '$root/config/config.php' || true"
  fi
  for p in "$root/data" "$root/apps" "$root/custom_apps" "$root/config" "$root/updater"; do
    [[ -e "$p" ]] && run "perm check: $p" bash -lc "stat -c '%a %U:%G %n' '$p' || true"
  done

  # Recent structured logs: metadata-only summary, no request/user/message/stack-trace content.
  nextcloud_recent_log_summary "$root/data/nextcloud.log"
  nextcloud_recent_log_summary "$root/nextcloud.log"
}

# WP-CLI always runs as www-data, never as root.
# Full-mode probes perform no intentional application updates or writes.
wp_query_capture() {
  local site="$1" user="$2" sql="$3" capture="$4"
  timeout "$WP_TIMEOUT" runuser -u "$user" -- env WP_CLI_CACHE_DIR="$WP_CACHE_DIR" \
      wp --path="$site" --skip-plugins --skip-themes --no-color \
      db query --skip-column-names "$sql" > "$capture" 2>&1
}

# Database-prefix inputs are always validated before interpolation into SQL.
wp_readonly_database_probes() {
  local site="$1" user="$2" prefix="$3" f="$TMPDIR/wp-db-result" table present
  if [[ ! "$prefix" =~ ^[[:alnum:]_]+$ ]]; then
    warn "Unsafe/unusual WordPress table prefix; SQL diagnostics skipped."
    return 0
  fi
  say ">> WordPress autoloaded options (count and bytes only)"
  if wp_query_capture "$site" "$user" "SELECT COUNT(*),COALESCE(SUM(LENGTH(option_value)),0) FROM ${prefix}options WHERE autoload IN ('yes','on','auto-on','auto');" "$f"; then
    head -n 3 "$f" | redact >> "$OUT"
  else
    warn "WordPress database read-only probe unavailable (autoload options)."
    head -n 2 "$f" | redact >> "$OUT"
    return 0
  fi
  say ">> WooCommerce HPOS option (if present)"
  if wp_query_capture "$site" "$user" "SELECT option_name, option_value FROM ${prefix}options WHERE option_name IN ('woocommerce_custom_orders_table_enabled','woocommerce_feature_custom_order_tables_enabled');" "$f"; then
    head -n 5 "$f" | redact >> "$OUT"
  fi
  for table in actionscheduler_actions woocommerce_sessions; do
    if ! wp_query_capture "$site" "$user" "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='${prefix}${table}';" "$f"; then
      info "Cannot check table existence for $table"
      continue
    fi
    present="$(head -n 1 "$f" | tr -cd '0-9')"
    [[ "$present" == 1 ]] || { info "Table ${prefix}${table} not present"; continue; }
    if [[ "$table" == actionscheduler_actions ]]; then
      say ">> Action Scheduler counts per status"
      if wp_query_capture "$site" "$user" "SELECT status,COUNT(*) FROM ${prefix}actionscheduler_actions GROUP BY status;" "$f"; then
        head -n 12 "$f" | redact >> "$OUT"
      else
        info "Action Scheduler status query unavailable"
      fi
      say ">> Action Scheduler overdue pending / failed counts"
      if wp_query_capture "$site" "$user" "SELECT (SELECT COUNT(*) FROM ${prefix}actionscheduler_actions WHERE status='pending' AND scheduled_date_gmt < UTC_TIMESTAMP() - INTERVAL 15 MINUTE) AS overdue_pending,(SELECT COUNT(*) FROM ${prefix}actionscheduler_actions WHERE status='failed') AS failed;" "$f"; then
        head -n 2 "$f" | redact >> "$OUT"
        local overdue failed
        read -r overdue failed < "$f" || true
        if [[ "$overdue" =~ ^[0-9]+$ && "$failed" =~ ^[0-9]+$ ]]; then
          if (( overdue >= 20 )); then warn "WordPress Action Scheduler has $overdue overdue pending actions (>15min)."; fi
          if (( failed > 0 )); then
            say ">> Action Scheduler failed actions: latest UTC date and recent counts"
            if wp_query_capture "$site" "$user" "SELECT COUNT(*),COALESCE(SUM(last_attempt_gmt >= UTC_TIMESTAMP() - INTERVAL 24 HOUR),0),COALESCE(SUM(last_attempt_gmt >= UTC_TIMESTAMP() - INTERVAL 7 DAY),0),MAX(last_attempt_gmt) FROM ${prefix}actionscheduler_actions WHERE status='failed';" "$f"; then
              head -n 2 "$f" | redact >> "$OUT"
              local total_failed recent_24h recent_7d latest_utc
              read -r total_failed recent_24h recent_7d latest_utc < "$f" || true
              if [[ "$recent_24h" =~ ^[0-9]+$ && "$recent_7d" =~ ^[0-9]+$ ]]; then
                if (( recent_24h > 0 )); then
                  warn "WordPress Action Scheduler has $recent_24h failed actions in the last 24h (historical total: $failed)."
                elif (( recent_7d > 0 )); then
                  info "Action Scheduler: $recent_7d failed within the last 7 days, none in last 24h (historical total: $failed)."
                else
                  info "Action Scheduler: $failed historical failed actions, none in last 7 days."
                fi
              fi
            else
              info "Failed-action age unavailable; total historical failures: $failed."
            fi
          fi
        fi
      fi
    else
      say ">> WooCommerce sessions (estimated table rows; inexpensive metadata query)"
      if wp_query_capture "$site" "$user" "SELECT table_rows,ROUND((data_length+index_length)/1048576,1) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='${prefix}woocommerce_sessions';" "$f"; then
        head -n 2 "$f" | redact >> "$OUT"
      fi
    fi
  done
}

mod_wordpress() {
  (( ${#WP_ROOTS[@]} > 0 )) || return 0
  sec "WordPress / WooCommerce (read-only WP-CLI and database queries)"
  local site user prefix
  for site in "${WP_ROOTS[@]}"; do
    say "WordPress root: $site"
    if [[ -e "$site/wp-config.php" ]]; then
      run "WordPress config permissions" stat -c '%a %U:%G %n' "$site/wp-config.php"
    fi
    if ! has wp || ! has runuser; then
      warn "wp or runuser unavailable; WordPress runtime checks skipped for $site."
      continue
    fi
    user=www-data
    if ! id "$user" >/dev/null 2>&1; then
      warn "www-data user unavailable; WordPress runtime checks skipped for $site."
      continue
    fi
    say "WP-CLI execution user: $user (without root privileges)"
    # WordPress is loaded by some WP-CLI commands. --skip-plugins and --skip-themes
    # limits side effects but must-use plugins and core hooks can still run.
    if [[ -z "$WP_CACHE_DIR" ]]; then
      WP_CACHE_DIR="$(mktemp -d -t stack_diag_wpcli.XXXXXX)"
      chown "$user" "$WP_CACHE_DIR"
      chmod 700 "$WP_CACHE_DIR"
    fi
    RUN_TIMEOUT="$WP_TIMEOUT" run "WordPress core version ($site)" \
      runuser -u "$user" -- env WP_CLI_CACHE_DIR="$WP_CACHE_DIR" \
      wp --path="$site" --skip-plugins --skip-themes --no-color core version
    RUN_TIMEOUT="$WP_TIMEOUT" run "WordPress plugins / WooCommerce / Redis plugins ($site)" \
      runuser -u "$user" -- env WP_CLI_CACHE_DIR="$WP_CACHE_DIR" \
      wp --path="$site" --skip-plugins --skip-themes --no-color \
      plugin list --fields=name,status,version,update --format=table
    RUN_TIMEOUT="$WP_TIMEOUT" run "WordPress scheduled events (count) ($site)" \
      runuser -u "$user" -- env WP_CLI_CACHE_DIR="$WP_CACHE_DIR" \
      wp --path="$site" --skip-plugins --skip-themes --no-color cron event list --format=count
    if timeout "$WP_TIMEOUT" runuser -u "$user" -- env WP_CLI_CACHE_DIR="$WP_CACHE_DIR" \
      wp --path="$site" --skip-plugins --skip-themes --no-color plugin is-active woocommerce >/dev/null 2>&1; then
      info "WooCommerce plugin is active on $site"
    else
      info "WooCommerce plugin not active (or status check unavailable) on $site"
    fi
    if [[ -f "$site/wp-content/object-cache.php" ]]; then
      info "WordPress object-cache.php drop-in present (backend not independently verified)."
    else
      info "No WordPress object-cache.php drop-in detected at conventional location."
    fi
    local cronfile="$TMPDIR/wp-config-result"
    if timeout "$WP_TIMEOUT" runuser -u "$user" -- env WP_CLI_CACHE_DIR="$WP_CACHE_DIR" \
        wp --path="$site" --skip-plugins --skip-themes --no-color \
        config get DISABLE_WP_CRON --type=constant > "$cronfile" 2>/dev/null; then
      info "DISABLE_WP_CRON: $(head -n 1 "$cronfile")"
    else
      info "DISABLE_WP_CRON not defined or not accessible (default is false)."
    fi
    prefix="$(timeout "$WP_TIMEOUT" runuser -u "$user" -- env WP_CLI_CACHE_DIR="$WP_CACHE_DIR" \
        wp --path="$site" --skip-plugins --skip-themes --no-color db prefix 2>/dev/null | head -n 1 || true)"
    if [[ -n "$prefix" ]]; then
      info "WordPress database table prefix detected (length ${#prefix})."
      wp_readonly_database_probes "$site" "$user" "$prefix"
    else
      warn "Cannot determine WordPress table prefix; database checks skipped."
    fi
  done
  if grep -RIlF 'wp-cron.php' /etc/cron.d /etc/crontab 2>/dev/null > "$TMPDIR/wp-cron-locations"; then
    say ">> Cron files that reference wp-cron.php (file paths only)"
    head -n 30 "$TMPDIR/wp-cron-locations" | redact >> "$OUT"
  else
    info "No wp-cron.php reference found in system cron files (may use a different scheduler)."
  fi
}

mod_zimbra() {
  sec "Zimbra"
  if [[ ! -d /opt/zimbra ]]; then
    warn "Zimbra path /opt/zimbra not present."
    return 0
  fi
  run "disk usage /opt/zimbra" bash -lc "df -hT /opt/zimbra 2>/dev/null || true; du -sh /opt/zimbra 2>/dev/null || true"
  if [[ -x /opt/zimbra/bin/zmcontrol ]]; then
    run "zmcontrol status" bash -lc "su - zimbra -c 'zmcontrol status' 2>/dev/null || true"
  else
    warn "zmcontrol not executable; installation may be incomplete."
  fi
  # common logs
  file_tail /var/log/zimbra.log
  file_tail /opt/zimbra/log/mailbox.log
  file_tail /opt/zimbra/log/nginx.log
  file_tail /opt/zimbra/log/audit.log

  # cert check
  check_cert_file /opt/zimbra/ssl/zimbra/server/server.crt
}

mod_elasticsearch() {
  sec "Elasticsearch"
  run "systemctl status elasticsearch (summary)" bash -lc "systemctl status elasticsearch --no-pager -l | head -n 120 || true"
  file_tail /var/log/elasticsearch/elasticsearch.log
  journal_unit elasticsearch.service

  # local API health (best effort)
  if has curl; then
    say ">> Elasticsearch local health (best effort)"
    curl -fsS --max-time 4 http://127.0.0.1:9200/_cluster/health?pretty 2>&1 | redact | tee -a "$OUT" >/dev/null || true
    say ""
    say ">> Elasticsearch nodes JVM heap (best effort)"
    curl -fsS --max-time 4 "http://127.0.0.1:9200/_nodes/stats/jvm?pretty" 2>&1 | head -n 200 | redact | tee -a "$OUT" >/dev/null || true
    say ""
  else
    warn "curl not present; Elasticsearch HTTP probes skipped."
  fi

  # heap heuristic (best effort)
  if [[ -r /etc/elasticsearch/jvm.options ]]; then
    run "jvm.options heap settings" bash -lc "egrep -n '^-Xms|-Xmx' /etc/elasticsearch/jvm.options || true"
  fi
}

mod_logstash() {
  sec "Logstash"
  run "systemctl status logstash (summary)" bash -lc "systemctl status logstash --no-pager -l | head -n 120 || true"
  file_tail /var/log/logstash/logstash-plain.log
  journal_unit logstash.service
  if [[ -d /etc/logstash/conf.d ]]; then
    run "pipelines/conf.d list" bash -lc "ls -lah /etc/logstash/conf.d 2>/dev/null || true; ls -lah /etc/logstash 2>/dev/null || true"
  fi
}

mod_zabbix() {
  sec "Zabbix"
  run "systemctl status zabbix (summary)" bash -lc "systemctl status zabbix-agent zabbix-agent2 zabbix-server zabbix-proxy --no-pager -l | head -n 140 || true"
  journal_unit zabbix-agent.service
  journal_unit zabbix-agent2.service
  journal_unit zabbix-server.service
  journal_unit zabbix-proxy.service
  file_tail /var/log/zabbix/zabbix_agentd.log
  file_tail /var/log/zabbix/zabbix_agent2.log
  file_tail /var/log/zabbix/zabbix_server.log
  file_tail /var/log/zabbix/zabbix_proxy.log

  # basic config sanity
  for c in /etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agent2.conf /etc/zabbix/zabbix_server.conf /etc/zabbix/zabbix_proxy.conf; do
    [[ -r "$c" ]] || continue
    run "config highlights: $c" bash -lc "egrep -n '^(Server|ServerActive|Hostname|ListenPort|DBHost|DBName|DBUser|TLS|AllowKey|DenyKey)=' '$c' 2>/dev/null || true"
  done
}

mod_django() {
  sec "Django / Python app layer (gunicorn/uwsgi/uvicorn/daphne)"
  run "matching units" bash -lc "systemctl list-units --type=service --all --no-legend | egrep -i '(gunicorn|uwsgi|daphne|uvicorn)' || true"
  # show status for each matching unit
  local units
  units="$(systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | egrep -i '(gunicorn|uwsgi|daphne|uvicorn)' || true)"
  if [[ -n "$units" ]]; then
    while IFS= read -r u; do
      [[ -n "$u" ]] || continue
      run "systemctl status $u (summary)" bash -lc "systemctl status '$u' --no-pager -l | head -n 120 || true"
      journal_unit "$u"
    done <<< "$units"
  else
    warn "No gunicorn/uwsgi/uvicorn/daphne units found; Django may be run differently."
  fi
}

mod_suitecrm() {
  sec "SuiteCRM"
  local root=""
  for d in "$SUITECRM_ROOT" /var/www/suitecrm /var/www/html/suitecrm /srv/suitecrm; do
    [[ -n "$d" && -d "$d" ]] && { root="$d"; break; }
  done
  if [[ -z "$root" ]]; then
    warn "SuiteCRM directory not found in standard locations."
    return 0
  fi
  say "[INFO] SuiteCRM root: $root"
  run "php -v" bash -lc "php -v 2>/dev/null | head -n 5 || true"
  run "web root perms (key dirs)" bash -lc "for p in cache custom upload; do [[ -d '$root/'\"\$p\" ]] && stat -c '%a %U:%G %n' '$root/'\"\$p\"; done"
  # cron hint
  run "cron grep (suitecrm)" bash -lc "crontab -l 2>/dev/null | egrep -i 'suitecrm|cron.php' || true; ls -lah /etc/cron.d 2>/dev/null | head -n 50 || true"
  # logs (best effort)
  file_tail "$root/suitecrm.log"
  file_tail "$root/sugarcrm.log"
}

# --------- additional read-only Raspberry Pi / infrastructure modules ----------
check_fstab_mounts() {
  sec "Expected persistent mounts"
  if [[ ! -r /etc/fstab ]]; then
    warn "Cannot read /etc/fstab"
    return 0
  fi
  local dev target fs opts rest
  while read -r dev target fs opts rest; do
    [[ -n "$dev" && "$dev" != \#* ]] || continue
    [[ "$target" == /* && "$target" != / && "$target" != /boot/firmware ]] || continue
    case "$fs" in ext2|ext3|ext4|xfs|btrfs|zfs|nfs|nfs4|cifs) ;; *) continue ;; esac
    if findmnt -rn --mountpoint "$target" >/dev/null 2>&1; then
      info "Mounted: $target ($(findmnt -rn -o SOURCE --mountpoint "$target" 2>/dev/null))"
    elif [[ ",$opts," == *,noauto,* ]]; then
      info "Intentionally unmounted (noauto): $target"
    elif [[ ",$opts," == *,nofail,* ]]; then
      warn "Optional filesystem not mounted: $target (fstab source: $dev)"
    else
      risk "Expected filesystem NOT mounted: $target (fstab source: $dev)"
      say "[CRITICAL] Required data path $target is missing; verify storage before jobs write into it."
    fi
  done < /etc/fstab
}

check_boot_storage_events() {
  sec "Current-boot storage / USB failures"
  if ! has journalctl; then
    info "journalctl unavailable; boot storage scan skipped"
    return 0
  fi
  local evidence="$TMPDIR/storage-events" kernel="$TMPDIR/kernel-events" line port product
  journalctl -k -b --no-pager >"$kernel" 2>/dev/null || true
  grep -Ei 'I/O error|device offline error|EXT4-fs error|JBD2.*(error|abort)|Aborting journal|USB disconnect|reset (SuperSpeed|high-speed) USB device|Buffer I/O error' "$kernel" > "$evidence" || true
  if [[ ! -s "$evidence" ]]; then
    info "No matching block-device / filesystem errors in current kernel journal."
  else
    say ">> Current-boot storage / USB event highlights"
    tail -n 60 "$evidence" | redact >> "$OUT"
    if grep -Eiq 'I/O error|device offline error|EXT4-fs error|JBD2.*(error|abort)|Aborting journal' "$evidence"; then
      say "[CRITICAL] Current boot contains block-device or filesystem I/O errors (even if a remount later succeeded)."
      info "These errors may be historical within this boot; check timestamps and current mount state before attributing an ongoing failure."
    fi
    while IFS= read -r line; do
      port="$(sed -nE 's/.*usb ([0-9]+-[0-9.]+): USB disconnect.*/\1/p' <<< "$line")"
      [[ -n "$port" ]] || continue
      product="$(grep -F "usb $port: Product:" "$kernel" | tail -n 1 | sed 's/.*Product: //' || true)"
      [[ -n "$product" ]] || product="unknown"
      if [[ "$product" =~ ([Cc]on[Bb]ee|[Dd]e[Cc][Oo][Nn][Zz]|[Zz]igbee) ]] && ! grep -Eiq 'I/O error|device offline error|EXT4-fs error|Aborting journal' "$evidence"; then
        info "USB $port disconnected/re-enumerated ($product); no block I/O errors."
      elif ! grep -Eiq 'I/O error|device offline error|EXT4-fs error|Aborting journal' "$evidence"; then
        warn "USB $port disconnected during this boot (device: $product). Verify whether expected."
      else
        info "USB $port disconnected (device: $product). Filesystem I/O errors occurred during this boot; per-device causal attribution is not established by this summary."
      fi
    done < <(grep 'USB disconnect' "$evidence" | sort -u)
  fi
  run "lsblk discard capabilities" lsblk -D
  if has lsusb; then
    run "USB topology / negotiated speed (informational)" lsusb -t
    info "A USB 2.0 disk can be intentional; only disconnection/I/O events warrant warnings."
  fi
}

check_pi_hardware() {
  if ! has vcgencmd && ! grep -qi 'Raspberry Pi' /proc/device-tree/model 2>/dev/null; then
    return 0
  fi
  sec "Raspberry Pi thermal / CPU / fan"
  if has vcgencmd; then
    run "SoC temperature" vcgencmd measure_temp
    run "Undervoltage / throttling state (hex bit mask)" vcgencmd get_throttled
  fi
  local p d name f b
  for p in /sys/devices/system/cpu/cpufreq/policy*; do
    [[ -d "$p" ]] || continue
    say "CPU policy: $p"
    for f in scaling_governor scaling_cur_freq scaling_min_freq scaling_max_freq; do
      [[ -r "$p/$f" ]] && say "  $f=$(cat "$p/$f")"
    done
  done
  for d in /sys/class/hwmon/hwmon*; do
    [[ -r "$d/name" ]] || continue
    name="$(cat "$d/name")"
    [[ "$name" == *fan* ]] || continue
    say "Fan controller: $name ($d)"
    for f in pwm1 pwm1_enable fan1_input; do
      [[ -r "$d/$f" ]] && say "  $f=$(cat "$d/$f")"
    done
  done
  for d in /sys/class/thermal/cooling_device*; do
    [[ -r "$d/type" ]] || continue
    name="$(cat "$d/type")"
    [[ "$name" == *fan* ]] || continue
    say "Cooling device: $name $(cat "$d/cur_state" 2>/dev/null)/$(cat "$d/max_state" 2>/dev/null)"
  done
}

check_rtc_ntp() {
  sec "RTC boot time / NTPsec / BIND"
  local d f bootline bootyear nowyear
  if [[ -r /sys/class/rtc/rtc0/hctosys ]]; then
    say "RTC hctosys: $(cat /sys/class/rtc/rtc0/hctosys)"
    for f in date time battery_voltage charging_voltage charging_voltage_max; do
      [[ -r "/sys/class/rtc/rtc0/$f" ]] && say "RTC $f: $(cat "/sys/class/rtc/rtc0/$f")"
    done
  fi
  bootline="$(journalctl -k -b --no-pager 2>/dev/null | grep -E 'setting system clock to [0-9]{4}-' | tail -n 1 || true)"
  if [[ -n "$bootline" ]]; then
    say "RTC kernel boot evidence: $bootline"
    bootyear="$(sed -nE 's/.*setting system clock to ([0-9]{4})-.*/\1/p' <<< "$bootline")"
    nowyear="$(date +%Y)"
    if [[ "$bootyear" =~ ^[0-9]{4}$ && "$nowyear" =~ ^[0-9]{4}$ ]] && (( 10#$bootyear < 10#$nowyear - 2 )); then
      say "[CRITICAL] RTC initialized this boot with an implausibly old year ($bootyear)."
    fi
  fi
  if has timedatectl; then
    run "NTP synchronization (systemd)" timedatectl show -p NTPSynchronized -p NTP
  fi
  if has ntpq; then
    run "NTP peers numeric" ntpq -pn
  fi
  if has dig && [[ -r /etc/resolv.conf ]] && (systemd_unit_active named.service || systemd_unit_active bind9.service); then
    local dns_normal dns_bogus
    dns_normal="$(dig +time=2 +tries=1 @127.0.0.1 example.org A +noall +comments +answer 2>&1 || true)"
    say ">> Local BIND resolver (example.org)"
    printf '%s\n' "$dns_normal" | redact >> "$OUT"
    if ! grep -q 'status: NOERROR' <<< "$dns_normal"; then
      warn "Local BIND recursive DNS probe did not return NOERROR."
    fi
    dns_bogus="$(dig +time=2 +tries=1 @127.0.0.1 dnssec-failed.org A +noall +comments +answer 2>&1 || true)"
    say ">> Local DNSSEC negative validation (dnssec-failed.org)"
    printf '%s\n' "$dns_bogus" | redact >> "$OUT"
    if grep -q 'status: SERVFAIL' <<< "$dns_bogus"; then
      info "DNSSEC negative test returned expected SERVFAIL (assuming recursion is otherwise healthy)."
    else
      warn "DNSSEC negative test did not return SERVFAIL; investigate validation configuration if unexpected."
    fi
  fi
  if has named-checkconf && (systemd_unit_active named.service || systemd_unit_active bind9.service); then
    run "BIND configuration syntax" named-checkconf
  fi
}

check_boot_jobs() {
  sec "Boot network readiness / job scheduling"
  if systemd_unit_exists systemd-networkd-wait-online.service; then
    run "networkd wait-online state" systemctl show systemd-networkd-wait-online.service -p ActiveState -p Result -p ExecMainStatus
    run "networkd wait-online boot log" bash -c 'journalctl -b -u systemd-networkd-wait-online.service --no-pager -n 25'
  fi
  if has systemctl; then
    run "Scheduled systemd timers" bash -c 'systemctl list-timers --all --no-pager --no-legend | head -n 50'
  fi
  if [[ -d /etc/cron.d ]]; then
    run "Cron drop-ins (names only)" bash -c 'find /etc/cron.d -maxdepth 1 -type f -printf "%f\n" | sort'
  fi
}

check_backup_freshness() {
  sec "Backup freshness (explicit paths only)"
  if [[ -z "$BACKUP_PATHS" ]]; then
    info "Backup freshness not assessed: set BACKUP_PATHS to actual backup directories. Cron presence is not proof of successful backups."
    return 0
  fi
  if ! [[ "$BACKUP_MAX_AGE_HOURS" =~ ^[0-9]+$ ]] || (( BACKUP_MAX_AGE_HOURS < 1 || BACKUP_MAX_AGE_HOURS > 8760 )); then
    warn "Invalid BACKUP_MAX_AGE_HOURS; skipping backup freshness check."
    return 0
  fi
  BACKUP_ASSESSED=1
  local dir newest now delta age
  now="$(date +%s)"
  for dir in $BACKUP_PATHS; do
    if [[ ! -d "$dir" ]]; then
      warn "Configured backup directory missing: $dir"
      continue
    fi
    # Avoid traversing other mounts and ensure the scan is bounded.
    newest="$(timeout 8 find "$dir" -xdev -maxdepth 3 -type f -printf '%T@\t%p\n' 2>/dev/null | sort -nr | head -n 1 || true)"
    if [[ -z "$newest" ]]; then
      warn "No recent backup file metadata found under $dir (depth <=3)."
      continue
    fi
    age="${newest%%.*}"
    if [[ "$age" =~ ^[0-9]+$ ]]; then
      delta=$(( (now - age) / 3600 ))
      info "Latest backup-file modification under $dir: ${delta}h ago (metadata only; restore not verified)."
      if (( delta > BACKUP_MAX_AGE_HOURS )); then
        warn "Backup files under $dir appear older than ${BACKUP_MAX_AGE_HOURS}h."
      fi
    fi
  done
}

check_docker() {
  if ! has docker; then return 0; fi
  sec "Docker health / logging"
  run "Docker server logging default" docker info --format '{{.LoggingDriver}}'
  run "Docker containers" docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
  # Avoid Docker inspect Config.Env; it may include secrets.
  local id
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    run "Container logging $id" docker inspect --format '{{.Name}} log={{.HostConfig.LogConfig.Type}} opts={{json .HostConfig.LogConfig.Config}} restart={{.HostConfig.RestartPolicy.Name}}' "$id"
  done < <(docker ps -q 2>/dev/null)
}

quick_overview() {
  sec "Meta"
  say "stack_diag version: ${VERSION}"
  say "host: ${HOST}"
  say "timestamp: ${TS}"
  say "mode: quick"
  say "output: ${OUT}"
  sec "Quick system status"
  run "uptime" uptime
  run "free -h" free -h
  run "df -hT" df -hT
  run "systemctl --failed" systemctl --failed
  run "lsblk" lsblk -f
}

sample_disk_writes() {
  sec "Storage write sample (60 seconds; read-only)"
  local f name before after delta bytes rate
  declare -A initial=()
  for f in /sys/block/*/stat; do
    [[ -r "$f" ]] || continue
    name="${f%/stat}"; name="${name##*/}"
    if [[ "$name" == loop* || "$name" == ram* || "$name" == zram* ]]; then continue; fi
    # Linux diskstats field 7 = 512-byte sectors written.
    initial["$name"]="$(awk '{print $7}' "$f")"
  done
  say "Sampling diskstats for 60 seconds; no write traffic generated by the sampler."
  sleep 60
  for f in /sys/block/*/stat; do
    [[ -r "$f" ]] || continue
    name="${f%/stat}"; name="${name##*/}"
    [[ -v "initial[$name]" ]] || continue
    after="$(awk '{print $7}' "$f")"
    before="${initial[$name]}"
    [[ "$after" =~ ^[0-9]+$ && "$before" =~ ^[0-9]+$ ]] || continue
    delta=$(( after - before ))
    (( delta >= 0 )) || continue
    bytes=$(( delta * 512 ))
    rate="$(awk -v bytes="$bytes" 'BEGIN {printf "%.2f MiB/min", bytes/1048576}')"
    say "$name: $rate (sample total $bytes bytes)"
  done
}

# --------- risk/perf heuristics ----------
heuristics() {
  sec "Heuristics (signal > noise)"

  # disk pressure
  local root_use
  root_use="$(df -P / | awk 'NR==2{gsub(/%/,"",$5);print $5}')"
  if [[ -n "$root_use" ]] && [[ "$root_use" -ge 90 ]]; then
    risk "Root filesystem usage is ${root_use}%. Expect cascading failures."
  elif [[ -n "$root_use" ]] && [[ "$root_use" -ge 80 ]]; then
    warn "Root filesystem usage is ${root_use}%. Plan cleanup or expansion."
  fi

  # swap activity
  if has vmstat; then
    local si so
    si="$(vmstat 1 2 | awk 'NR==4{print $7}' 2>/dev/null || echo 0)"
    so="$(vmstat 1 2 | awk 'NR==4{print $8}' 2>/dev/null || echo 0)"
    if [[ "${si:-0}" -gt 0 || "${so:-0}" -gt 0 ]]; then
      perf "Swap in/out detected (si=${si}, so=${so}). Memory pressure likely."
    fi
  fi

  # failed units
  local failed_units
  failed_units="$(systemctl --failed --no-legend 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${failed_units:-0}" -gt 0 ]]; then
    fail "There are ${failed_units} failed systemd units. See Systemd health section."
  fi

  # open exposure: redis on non-local
  if port_listen_contains ":6379" && has ss; then
    if ss -ltnp 2>/dev/null | grep -F ":6379" | grep -vq "127.0.0.1"; then
      risk "Redis appears exposed beyond localhost. Validate bind/TLS/auth immediately."
    fi
  fi

  # elasticsearch open exposure
  if port_listen_contains ":9200" && has ss; then
    if ss -ltnp 2>/dev/null | grep -F ":9200" | grep -vq "127.0.0.1"; then
      warn "Elasticsearch appears exposed beyond localhost. Ensure auth/TLS/network policy."
    fi
  fi

  # nginx/apache conflict (both active)
  if systemd_unit_active nginx.service && systemd_unit_active apache2.service; then
    warn "Both nginx and apache2 are active. Ensure intentional reverse-proxy chain and no port conflicts."
  fi
}

# --------- main ----------
write_health_summary() {
  local critical warning failed tmp="$TMPDIR/body"
  critical="$(grep -c '^\[CRITICAL\]' "$OUT" || true)"
  warning="$(grep -Ec '^\[(WARN|RISK)\]' "$OUT" || true)"
  failed="$(grep -Ec '^\[CHECK-(TIMEOUT|FAILED)\]' "$OUT" || true)"
  cp "$OUT" "$tmp"
  : > "$OUT"
  say "STACK DIAG HEALTH SUMMARY"
  say "Host: $HOST | Version: $VERSION | Mode: $MODE"
  say "Critical: $critical | Warnings: $warning | Executed command failures/timeouts: $failed (application findings counted separately)"
  if [[ "$MODE" == full ]]; then
    if (( BACKUP_ASSESSED == 1 )); then
      say "Backup freshness: CHECKED (metadata only; restore not verified)"
    else
      say "Backup freshness: NOT ASSESSED (no valid BACKUP_PATHS supplied)"
    fi
  fi
  if (( critical > 0 )); then
    grep '^\[CRITICAL\]' "$tmp" >> "$OUT" || true
  fi
  say "Full evidence follows below."
  say ""
  cat "$tmp" >> "$OUT"
}

main() {
  : > "$OUT"
  discover_applications
  if [[ "$MODE" == "storage-write" ]]; then
    sec "Meta"
    say "stack_diag version: ${VERSION}"
    say "host: ${HOST}"
    say "mode: storage-write"
    say "output: ${OUT}"
    sample_disk_writes
  elif [[ "$MODE" == "mysqltuner" ]]; then
    sec "Meta"
    say "stack_diag version: ${VERSION}"
    say "host: ${HOST}"
    say "mode: mysqltuner"
    say "output: ${OUT}"
    mod_mysqltuner
  elif [[ "$MODE" == "quick" ]]; then
    quick_overview
    check_fstab_mounts
    check_boot_storage_events
    check_pi_hardware
    check_rtc_ntp
    check_docker
  else
    sys_overview
    check_domain_tls
    check_fstab_mounts
    check_boot_storage_events
    check_pi_hardware
    check_rtc_ntp
    check_boot_jobs
    check_backup_freshness
    check_docker

    sec "Service auto-detection matrix"
    for s in nginx apache postfix mysql redis nextcloud wordpress zimbra elasticsearch logstash zabbix_agent zabbix_srv django suitecrm; do
      if detect "$s"; then
        say "[DETECT] $s: present"
      else
        say "[DETECT] $s: not found"
      fi
    done
    say ""

    detect nginx          && mod_nginx
    detect apache         && mod_apache
    detect postfix        && mod_postfix
    detect mysql          && mod_mysql
    detect redis          && mod_redis
    detect nextcloud      && mod_nextcloud
    detect wordpress      && mod_wordpress
    detect zimbra         && mod_zimbra
    detect elasticsearch  && mod_elasticsearch
    detect logstash       && mod_logstash
    (detect zabbix_agent || detect zabbix_srv) && mod_zabbix
    detect django         && mod_django
    detect suitecrm       && mod_suitecrm

    heuristics
  fi
  sec "Done"
  say "Report written to: $OUT"
  write_health_summary
  printf 'Report written to: %s\n' "$OUT"
}

main "$@"
