Copyright (c) 2026, Mnheia <mnheia@gmail.com>

# stack-diagnose

A best-effort, read-oriented Bash diagnostic script for Debian and Ubuntu servers.
It detects installed services and writes a timestamped report to `/tmp` with mode `0600`.

## Quick start

```bash
sudo bash stack-diagnose.sh              # full report (default)
sudo bash stack-diagnose.sh --quick      # essential health checks
sudo bash stack-diagnose.sh --help
```

The script prints the report path after completion. The filename has the form
`/tmp/stack_diag_<hostname>_<YYYYMMDD_HHMMSS>.log`.

## Modes

| Mode | Behavior |
| --- | --- |
| `--full` | OS, storage, network, time, security, service checks, detected applications, and heuristics (default). |
| `--quick` | Essential system/boot/storage, Raspberry Pi, NTP/DNS and Docker checks. |
| `--storage-write` | Read-only sampling of `/sys/block` disk write counters over 60 seconds. Does not generate writes itself. |
| `--mysqltuner` | Separate, optional local MySQLTuner run, with a 120-second timeout. Never automatically installed or run by `--full`. |
| `--help` | Command help. |

## Coverage

- Operating system, CPU, RAM, swap, partitions, mounts, network ports and time synchronization.
- SSH settings, firewall, Fail2ban, AppArmor/SELinux, systemd failures and relevant boot logs.
- DNS/TLS checks when `DOMAIN` is set; NTPsec peers, BIND configuration and local DNSSEC validation where available.
- Persistent mount validation and current-boot storage/USB error reporting; negotiated USB link speed.
- Raspberry Pi thermal, CPU governor, undervoltage, throttling, fan and RTC state where supported.
- Apache and Nginx; CLI/Apache PHP OPcache configuration checks, including PHP 8.5 built-in OPcache semantics.
- Postfix queue counts, including deferred or held messages, and mail-service logs.
- MySQL/MariaDB local Unix socket by default; connection limits, InnoDB activity, table sizes, temporary table ratios and short-uptime caveats.
- Redis via Unix socket or local TCP; memory, evictions, policy, keyspace counters and transport.
- Nextcloud via local `occ`, including maintenance, caching/locking configuration, scheduled jobs, permissions and bounded recent-log counts.
- WordPress/WooCommerce via local WP-CLI, including core/plugins, cron, HPOS, autoloaded options, Action Scheduler age/counts and sessions.
- Docker container status and per-container logging configuration (without container environment variables).
- Zimbra, Elasticsearch, Logstash, Zabbix, Django application servers and SuiteCRM when detected.
- Optional backup-file modification-time checks; these are NOT backup integrity or restore tests.

### Environment settings

| Variable | Purpose |
| --- | --- |
| `DOMAIN` | Optional public DNS/TLS checks. |
| `TEST_EMAIL` | Optional Postfix recipient routing verification (`sendmail -bv`); no message content sent. |
| `REDIS_AUTH` / `REDISCLI_AUTH` | Authentication, supplied through environment rather than CLI args. |
| `REDIS_SOCKET` | Override Redis Unix socket path. |
| `MYSQL_USER`, `MYSQL_PWD`, `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_SOCKET` | Database connection overrides; local Unix socket is the default. |
| `WP_ROOT` | Additional WordPress root; also discovers common paths and enabled Apache document roots. |
| `NC_ROOT` / `NEXTCLOUD_ROOT` | Additional Nextcloud root (`NEXTCLOUD_ROOT` is retained for backward compatibility). |
| `SUITECRM_ROOT` | Optional SuiteCRM location. |
| `BACKUP_PATHS` | Whitespace-separated directories to scan for recent files. Leave unset to report “not assessed”. |
| `BACKUP_MAX_AGE_HOURS` | Modification-time threshold; default 36 hours. |

Examples:

```bash
sudo env DOMAIN=example.com bash stack-diagnose.sh --full
sudo env BACKUP_PATHS='/var/backups /srv/backups' BACKUP_MAX_AGE_HOURS=48 \
  bash stack-diagnose.sh --full
sudo bash stack-diagnose.sh --mysqltuner  # if mysqltuner is already installed
```

## Safety and limitations

- No configuration edits, package installation, service restarts, database writes, or automatic cleanups are intentionally performed.
- Full mode may bootstrap WordPress through WP-CLI; plugins/hooks can still update caches or transients during initialization. Use staging when strict zero-side-effect behavior is required.
- Read-only `occ` and other application commands can append normal application audit logs.
- Never equate successful command execution with a healthy application; application warnings have a separate health classification.
- A past block-device I/O failure remains important even when the filesystem has since remounted successfully.
- A running database or backup cron entry does not prove recoverability. Backup freshness is explicitly shown as unassessed unless configured.
- MySQLTuner is optional and potentially expensive on a production database. Prefer representative uptime and investigate its recommendations before changing settings.
- Log content is redacted on a best-effort basis, not guaranteed anonymized. Nextcloud summary avoids request and message bodies; other service logs may still contain usernames, IPs and email addresses.
- Keep generated reports private. **Never commit them or production credentials to this public repository.**

## Requirements

Bash, core Linux utilities, optional `timeout` and systemd tooling; full coverage requires each service's own utilities. WP-CLI, Redis CLI, and MySQL/MariaDB clients are used only if installed. The optional MySQLTuner mode requires a local `mysqltuner` executable.

## Bugs and licensing

Report bugs and feature requests at <https://github.com/mnheia/stack-diagnose/issues>.
GPLv3; see `LICENSE` and `COPYRIGHT`.
