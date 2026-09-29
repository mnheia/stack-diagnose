Copyright (c) 2026, Mnheia <mnheia@gmail.com>

# stack-diagnose
A read-only diagnostic script for Debian and Ubuntu servers.

It collects a lightweight system overview, auto-detects common infrastructure and application services, and writes a timestamped diagnostic report to `/tmp`.

# Checks
The script includes best-effort diagnostics for:

- operating system, kernel, CPU, memory and storage
- network configuration, listening ports and time synchronization
- basic security and systemd health
- DNS and TLS checks for an optional domain
- Nginx and Apache
- Postfix
- MySQL / MariaDB
- Redis
- Nextcloud
- Zimbra
- Elasticsearch and Logstash
- Zabbix agent, server and proxy
- Django application services using Gunicorn, uWSGI, Uvicorn or Daphne
- SuiteCRM

It also reports a small set of higher-signal warnings for conditions such as disk pressure, swap activity, failed systemd units and unexpected Redis or Elasticsearch exposure.

# Usage
Run as root for the most complete result:

```bash
sudo ./stack-diagnose.sh
```

Optional environment variables:

```bash
sudo env DOMAIN=example.com \
  TEST_EMAIL=ops@example.com \
  NEXTCLOUD_ROOT=/var/www/nextcloud \
  SUITECRM_ROOT=/var/www/suitecrm \
  ./stack-diagnose.sh
```

Database and Redis probes can also use:

```bash
MYSQL_USER=root
MYSQL_PWD=...
MYSQL_HOST=localhost
MYSQL_PORT=3306
REDIS_AUTH=...
```

The report is written to a file similar to:

```text
/tmp/stack-diagnose_server.example.com_20260930_001500.log
```

# Safety
The script is intended to be read-only:

- it does not modify configuration
- it does not restart services
- it uses short timeouts for external probes
- generated report files use restrictive permissions
- common password, token and authorization patterns are redacted from captured output

Diagnostic reports can still contain sensitive operational information such as hostnames, IP addresses, usernames, service configuration, log messages and filesystem paths. Review a report before sharing it.

# Requirements
- Bash
- standard Linux utilities
- systemd tools for the fullest coverage

Additional service-specific commands are used only when they are available.

# Bugs
Please report any bugs or feature requests through the web interface at https://github.com/mnheia/stack-diagnose/issues
