#!/usr/bin/env bash
# stack-diagnose.sh - Debian/Ubuntu server diagnostics (read-only)
# Auto-detects common services (nginx, apache, nextcloud, zimbra, elasticsearch, logstash, zabbix, django/gunicorn/uwsgi, suitecrm, postfix, mysql/mariadb, redis)
#
# Safe-by-default:
# - No config writes
# - No service restarts
# - Uses lightweight commands + tail/journal snippets
#
# Optional env:
#   DOMAIN=example.com          # for DNS/MX/TLS SNI checks where applicable
#   TEST_EMAIL=ops@example.com  # postfix routing probe (sendmail -bv) - no mail sent
#   REDIS_AUTH=...              # Redis password if authentication is required
#   MYSQL_USER=root             # mysql client user (defaults to root)
#   MYSQL_PWD=...               # MySQL client password (optional)
#   NEXTCLOUD_ROOT=/var/www/nextcloud  # optional custom Nextcloud root
#   SUITECRM_ROOT=/var/www/suitecrm    # optional custom SuiteCRM root
#   MYSQL_HOST=localhost
#   MYSQL_PORT=3306
#
# Usage:
#   sudo bash stack-diagnose.sh
#   sudo DOMAIN=example.com bash stack-diagnose.sh
#
set -Eeuo pipefail
umask 077

# Copyright (c) 2026, Mnheia <mnheia@gmail.com>
#
# This module is free software; you can redistribute it and/or modify it
# under the terms of GNU general public license (gpl) version 3.
# See the LICENSE file for details.

VERSION="2026-09-30"

# --------- globals ----------
HOST="$(hostname -f 2>/dev/null || hostname)"
TS="$(date +'%Y%m%d_%H%M%S')"
OUT="/tmp/stack-diagnose_${HOST}_${TS}.log"
TMPDIR="$(mktemp -d -t stack-diagnose.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

DOMAIN="${DOMAIN:-}"
TEST_EMAIL="${TEST_EMAIL:-}"
REDIS_AUTH="${REDIS_AUTH:-${REDISCLI_AUTH:-}}"
NEXTCLOUD_ROOT="${NEXTCLOUD_ROOT:-}"
SUITECRM_ROOT="${SUITECRM_ROOT:-}"

MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PWD="${MYSQL_PWD:-}"
MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"

# soft limits
JOURNAL_LINES=200
LOG_TAIL_LINES=200
CMD_TIMEOUT=8

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
  # run "<label>" <cmd...>
  local label="$1"; shift
  say ">> ${label}"
  if has timeout; then
    timeout "${CMD_TIMEOUT}"s "$@" 2>&1 | sed 's/\r$//' | redact | tee -a "$OUT" >/dev/null || true
  else
    "$@" 2>&1 | sed 's/\r$//' | redact | tee -a "$OUT" >/dev/null || true
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
    say ">> journalctl -u ${unit} -n ${JOURNAL_LINES} --no-pager"
    journalctl -u "$unit" -n "${JOURNAL_LINES}" --no-pager 2>&1 | redact | tee -a "$OUT" >/dev/null || true
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
  systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "$unit"
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
    mysql)        systemd_unit_exists mysql.service || systemd_unit_exists mariadb.service || has mysql ;;
    redis)        systemd_unit_exists redis-server.service || systemd_unit_exists redis.service || has redis-cli ;;
    nextcloud)    find_nextcloud_root >/dev/null 2>&1 ;;
    zimbra)       [[ -x /opt/zimbra/bin/zmcontrol || -d /opt/zimbra ]] ;;
    elasticsearch) systemd_unit_exists elasticsearch.service || has elasticsearch || port_listen_contains ":9200" ;;
    logstash)     systemd_unit_exists logstash.service || has logstash ;;
    zabbix_agent) systemd_unit_exists zabbix-agent.service || systemd_unit_exists zabbix-agent2.service || has zabbix_agentd ;;
    zabbix_srv)   systemd_unit_exists zabbix-server.service || systemd_unit_exists zabbix-proxy.service ;;
    django)       systemctl list-units --type=service --all --no-legend 2>/dev/null | grep -Eiq '(gunicorn|uwsgi|daphne|uvicorn)' ;;
    suitecrm)     find_suitecrm_root >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

# --------- core system checks ----------
sys_overview() {
  sec "Meta"
  say "stack-diagnose version: ${VERSION}"
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
  run "last reboot (last -x | head)" bash -lc "last -x | head -n 10" || true

  sec "CPU + Memory"
  run "lscpu (summary)" bash -lc "lscpu | egrep -i 'model name|socket|cpu\\(s\\)|thread|core|mhz|virtualization' || true"
  run "free -h" free -h
  run "vmstat 1 5" bash -lc "vmstat 1 5 || true"
  run "top (snapshot)" bash -lc "top -b -n 1 | head -n 25 || true"

  sec "Storage"
  run "df -hT" df -hT
  run "lsblk -f" lsblk -f || true
  run "mount (interesting)" bash -lc "mount | egrep -i 'ext4|xfs|btrfs|zfs|nfs|cifs|fuse' || true"
  run "largest dirs (/var /home /opt) quick" bash -lc "du -x -h -d 1 /var /home /opt 2>/dev/null | sort -h | tail -n 30 || true"

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
  file_tail /var/log/mail.log
  file_tail /var/log/mail.err
  journal_unit postfix.service
}

mysql_exec() {
  # best effort; avoids prompting
  local q="$1"
  local args=(mysql --protocol=tcp -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" --connect-timeout=5 --batch --skip-column-names)
  if [[ -n "$MYSQL_PWD" ]]; then
    MYSQL_PWD="$MYSQL_PWD" "${args[@]}" -e "$q" 2>/dev/null || true
  else
    "${args[@]}" -e "$q" 2>/dev/null || true
  fi
}

mod_mysql() {
  sec "MySQL/MariaDB"
  run "systemctl status mysql/mariadb (summary)" bash -lc "systemctl status mysql mariadb --no-pager -l | head -n 120 || true"
  if has mysql; then
    run "mysql --version" mysql --version
    say ">> MySQL quick probes (best effort, may be empty if auth blocks)"
    {
      echo "### @@version, @@version_comment"
      mysql_exec "SELECT @@version, @@version_comment;"
      echo ""
      echo "### uptime, threads, connections"
      mysql_exec "SHOW GLOBAL STATUS LIKE 'Uptime';"
      mysql_exec "SHOW GLOBAL STATUS LIKE 'Threads_connected';"
      mysql_exec "SHOW GLOBAL STATUS LIKE 'Max_used_connections';"
      echo ""
      echo "### innodb buffer pool + log size"
      mysql_exec "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('innodb_buffer_pool_size','innodb_log_file_size','max_connections','tmp_table_size','max_heap_table_size');"
      echo ""
      echo "### top 10 tables by size (all schemas)"
      mysql_exec "SELECT table_schema, table_name, ROUND((data_length+index_length)/1024/1024,1) AS mb FROM information_schema.tables ORDER BY (data_length+index_length) DESC LIMIT 10;"
    } 2>&1 | redact | tee -a "$OUT" >/dev/null || true
    say ""
  else
    warn "mysql client not found."
  fi
  file_tail /var/log/mysql/error.log
  file_tail /var/log/mariadb/mariadb.log
  journal_unit mysql.service
  journal_unit mariadb.service
}

redis_exec() {
  if [[ -n "$REDIS_AUTH" ]]; then
    REDISCLI_AUTH="$REDIS_AUTH" redis-cli "$@"
  else
    redis-cli "$@"
  fi
}

mod_redis() {
  sec "Redis"
  run "systemctl status redis (summary)" bash -lc "systemctl status redis redis-server --no-pager -l | head -n 120 || true"
  if has redis-cli; then
    say ">> redis-cli PING"
    redis_exec PING 2>&1 | redact | tee -a "$OUT" >/dev/null || true
    say ""

    say ">> redis-cli INFO (filtered)"
    redis_exec INFO 2>/dev/null | egrep -i 'redis_version|uptime_in_seconds|connected_clients|used_memory_human|maxmemory_human|maxmemory_policy|evicted_keys|keyspace_hits|keyspace_misses' \
      2>&1 | redact | tee -a "$OUT" >/dev/null || true
    say ""
  else
    warn "redis-cli not found."
  fi
  file_tail /var/log/redis/redis-server.log
  journal_unit redis-server.service
  journal_unit redis.service
}

find_nextcloud_root() {
  if [[ -n "$NEXTCLOUD_ROOT" && -f "$NEXTCLOUD_ROOT/occ" ]]; then
    echo "$NEXTCLOUD_ROOT"
    return 0
  fi

  local d
  for d in /var/www/nextcloud /var/www/html/nextcloud /srv/nextcloud /opt/nextcloud; do
    [[ -f "$d/occ" ]] && { echo "$d"; return 0; }
  done
  return 1
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
  run "occ status (read-only)" bash -lc "cd '$root' && sudo -u www-data php occ status 2>/dev/null || php occ status 2>/dev/null || true"
  run "occ config:system get trusted_domains" bash -lc "cd '$root' && sudo -u www-data php occ config:system:get trusted_domains 2>/dev/null || true"
  run "occ maintenance:mode" bash -lc "cd '$root' && sudo -u www-data php occ maintenance:mode 2>/dev/null || true"
  run "occ background jobs mode" bash -lc "cd '$root' && sudo -u www-data php occ background:status 2>/dev/null || true"
  run "occ app:list (enabled only)" bash -lc "cd '$root' && sudo -u www-data php occ app:list --enabled 2>/dev/null | head -n 200 || true"

  # permissions sanity
  if [[ -f "$root/config/config.php" ]]; then
    run "config.php perms" bash -lc "ls -l '$root/config/config.php' && stat -c '%a %U:%G %n' '$root/config/config.php' || true"
  fi
  for p in "$root/data" "$root/apps" "$root/custom_apps" "$root/config" "$root/updater"; do
    [[ -e "$p" ]] && run "perm check: $p" bash -lc "stat -c '%a %U:%G %n' '$p' || true"
  done

  # logs
  file_tail "$root/data/nextcloud.log"
  file_tail "$root/nextcloud.log"
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
  file_tail /var/log/zabbix_proxy.conf; do
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

find_suitecrm_root() {
  if [[ -n "$SUITECRM_ROOT" && -d "$SUITECRM_ROOT" ]]; then
    echo "$SUITECRM_ROOT"
    return 0
  fi

  local d
  for d in /var/www/suitecrm /var/www/html/suitecrm /srv/suitecrm /opt/suitecrm; do
    [[ -d "$d" ]] && { echo "$d"; return 0; }
  done
  return 1
}

mod_suitecrm() {
  sec "SuiteCRM"
  local root
  if ! root="$(find_suitecrm_root)"; then
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
main() {
  : > "$OUT"
  sys_overview
  check_domain_tls

  # detect + run modules
  sec "Service auto-detection matrix"
  for s in nginx apache postfix mysql redis nextcloud zimbra elasticsearch logstash zabbix_agent zabbix_srv django suitecrm; do
    if detect "$s"; then
      say "[DETECT] $s: present"
    else
      say "[DETECT] $s: not found"
    fi
  done
  say ""

  # run modules conditionally
  detect nginx          && mod_nginx
  detect apache         && mod_apache
  detect postfix        && mod_postfix
  detect mysql          && mod_mysql
  detect redis          && mod_redis
  detect nextcloud      && mod_nextcloud
  detect zimbra         && mod_zimbra
  detect elasticsearch  && mod_elasticsearch
  detect logstash       && mod_logstash
  (detect zabbix_agent || detect zabbix_srv) && mod_zabbix
  detect django         && mod_django
  detect suitecrm       && mod_suitecrm

  heuristics

  sec "Done"
  say "Report written to: $OUT"
  say "Tip: ship it to a ticket or paste key sections. For diffing hosts: run on both and compare."
}

main "$@"
