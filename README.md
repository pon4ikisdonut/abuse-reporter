# abuse-reporter

An automatic daemon for monitoring nginx access logs across multiple sites, detecting suspicious and malicious requests, automatically sending reports to AbuseIPDB, and banning offenders via Cloudflare Access Rules.

Feel free to open issues, submit pull requests, and so on!

---

## Features

- Monitor multiple domains/sites at the same time via `SITES_JSON` in `.env`.
- Incremental log parsing: the file position is stored in `state_file`, so old lines are not re-read.
- `CF-Connecting-IP` support: if the access log contains the real client IP from Cloudflare, the script will use that exact IP.
- A large set of detection patterns: secrets and config files, `.git`, `.svn`, `.ssh`, CMS endpoints, path traversal, SQLi, XSS, RCE, Log4Shell/log4j, and more.
- A narrowed `select ... from` pattern with filtering by suspicious HTTP statuses to reduce false positives on normal requests.
- Per-IP activity aggregation within a single cycle: request count, unique URIs, HTTP methods, statuses, and timestamps of the first and last attack.
- IP checking via AbuseIPDB `check` before reporting.
- Duplicate reports are skipped only if the IP was already reported by this same script using your unique tag in the comment.
- Automatic IP banning through Cloudflare Access Rules with `permanent` and `temporary` modes.
- A local SQLite database for `reported_ips` history and a separate `ip_cache` for reverse DNS and AbuseIPDB responses.
- Whitelisting by single IPs, CIDR subnets, ASN, and reverse DNS/hostname patterns.
- Basic AbuseIPDB rate-limit protection: request intervals, serialized `report` calls, handling of `429`, `Retry-After`, and `X-RateLimit-*`.

---

## Requirements and Dependencies

### Python

Python 3.8+ is required.

There is only one external dependency:

```bash
pip install requests
```

The following standard Python modules are used:

- `ipaddress`
- `json`
- `os`
- `re`
- `socket`
- `sqlite3`
- `threading`
- `time`
- `concurrent.futures`
- `datetime`
- `typing`
- `urllib.parse`

### System Requirements

The script needs permissions for:

- reading nginx access logs;
- writing to the SQLite database;
- writing to `state_file`.

If you do not run it as root:

- grant the user read access to the logs, for example via the `adm` or `nginx` group;
- set `DB_FILE` to a path such as `/var/lib/abuse-reporter/abuse_reporter.db` or somewhere in the user’s home directory;
- make sure the user can create and update `state_file`.

### Third-Party Services

- An AbuseIPDB account with an API key.
- A Cloudflare account with an API token and Zone ID for each domain.

---

## Configuration

### 1. `.env` as the configuration center

Copy the example and fill it in:

```bash
cp .env.example .env
```

The main idea is that everything is configured through `.env`, not by editing the Python code.

### 2. Example `.env`

```dotenv
ABUSE_API_KEY=your_abuseipdb_api_key
CF_API_TOKEN=your_cloudflare_api_token
SITES_JSON=[{"domain":"example1.com","log_file":"/var/log/nginx/example1_access.log","state_file":"/tmp/example1_abuse_last_pos.txt","cf_zone_id":"zone_id_1"},{"domain":"example2.com","log_file":"/var/log/nginx/example2_access.log","state_file":"/tmp/example2_abuse_last_pos.txt","cf_zone_id":"zone_id_2"}]
DB_FILE=/var/db/abuse_reporter.db
CHECK_INTERVAL_SECONDS=60
ABUSE_CHECK_MAX_AGE_DAYS=90
ABUSE_REPORT_CATEGORIES=15,21
ABUSE_REQUEST_TIMEOUT=15
ABUSE_COMMENT_MAX_LEN=1024
REVERSE_DNS_CACHE_HOURS=72
ABUSE_CHECK_CACHE_HOURS=24
ABUSE_MIN_REQUEST_INTERVAL_SECONDS=2.0
ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS=2.0
ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS=15.0
PROCESS_WORKERS=2
SQLITE_TIMEOUT=30
CF_BAN_MODE=permanent
CF_TEMP_BAN_MINUTES=60
CF_REQUEST_TIMEOUT=15
WHITE_LIST_IPS=127.0.0.1,::1
WHITE_LIST_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,100.64.0.0/10,::1/128,fc00::/7,fe80::/10
WHITE_LIST_ASNS=
WHITE_LIST_HOSTNAME_PATTERNS=\.googlebot\.com$,\.google\.com$,\.search\.msn\.com$,\.bing\.com$,\.yandex\.ru$,\.yandex\.net$,\.crawl\.baidu\.com$
```

### 3. What is stored in `.env`

#### API and Cloudflare

- `ABUSE_API_KEY` — AbuseIPDB API key.
- `CF_API_TOKEN` — Cloudflare API token.
- `CF_BAN_MODE` — `permanent` or `temporary`.
- `CF_TEMP_BAN_MINUTES` — temporary ban duration in minutes.
- `CF_REQUEST_TIMEOUT` — timeout for Cloudflare requests.

#### Sites

The list of sites is stored in `SITES_JSON` as a JSON array of objects.

Site object fields:

- `domain` — the domain that will appear in the report comment;
- `log_file` — path to the nginx access log;
- `state_file` — file containing the last read position;
- `cf_zone_id` — Cloudflare Zone ID used to block the IP in the corresponding zone.

#### Core Parameters

- `DB_FILE` — path to the SQLite database.
- `CHECK_INTERVAL_SECONDS` — interval between processing cycles.
- `ABUSE_CHECK_MAX_AGE_DAYS` — history depth for `check` reports.
- `ABUSE_REPORT_CATEGORIES` — categories sent to AbuseIPDB.
- `ABUSE_REQUEST_TIMEOUT` — timeout for HTTP requests to AbuseIPDB.
- `ABUSE_COMMENT_MAX_LEN` — maximum length of the report comment.
- `REVERSE_DNS_CACHE_HOURS` — reverse DNS cache TTL.
- `ABUSE_CHECK_CACHE_HOURS` — cache TTL for `check` results.
- `ABUSE_MIN_REQUEST_INTERVAL_SECONDS` — base minimum interval between AbuseIPDB requests.
- `ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS` — separate interval for `check`.
- `ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS` — separate interval for `report`.
- `PROCESS_WORKERS` — number of worker threads for per-IP processing inside a single site.
- `SQLITE_TIMEOUT` — timeout while waiting on SQLite locks.

#### Whitelist

- `WHITE_LIST_IPS` — comma-separated list of single IPs.
- `WHITE_LIST_CIDRS` — comma-separated list of subnets.
- `WHITE_LIST_ASNS` — comma-separated list of ASNs, for example `AS15169,AS32934`.
- `WHITE_LIST_HOSTNAME_PATTERNS` — comma-separated regex patterns for hostnames.

Additionally, the script automatically skips private, reserved, link-local, loopback, multicast, and unspecified addresses via `ipaddress`.

---

## nginx Log Format

By default, `LOG_PATTERN` is designed for an access log format close to `combined`:

```text
<IP> - - [<date>] "<METHOD> <URL> HTTP/1.1" <status> ...
```

If a log line contains `CF-Connecting-IP` or a common variation of it, the script will try to extract the real client address from there.

If you use a custom `log_format`, you need to adapt `LOG_PATTERN` or the log line format so the script can extract the IP, date, method, URL, and status.

---

## How the Script Works

1. Loads `.env` and validates `SITES_JSON`.
2. Creates the SQLite tables `reported_ips` and `ip_cache` if they do not already exist.
3. For each site, reads the log only from the last saved position.
4. Parses the IP, URL, method, status, and timestamp.
5. Searches for URL matches against the detection patterns.
6. Aggregates malicious activity per IP within the current cycle.
7. Checks whether the IP is already present in the local `reported_ips` table for the given domain.
8. Runs the IP through the local whitelist: single IPs, CIDR ranges, private/reserved ranges, and reverse DNS.
9. Performs an AbuseIPDB `check` with `verbose=True` to get the list of previous `reports`, if the IP has not already been filtered out.
10. Applies additional whitelist checks based on AbuseIPDB data: `isPublic`, ASN, and `usageType`.
11. Looks for its own unique `report_tag` in past report comments.
12. If your report already exists, a duplicate report is not sent, but a Cloudflare ban may still be applied.
13. If temporary bans are enabled and an old ban has expired, the rule may be re-created.
14. If your report is not found, a new `report` is sent to AbuseIPDB.
15. After that, the IP is blocked via Cloudflare.
16. The result is written to SQLite.

---

## SQLite Structure

### `reported_ips` Table

Stores the fact that an IP was processed for a specific domain.

Fields:

- `ip`
- `domain`
- `reported_at`
- `cf_banned`
- `first_seen`
- `last_seen`
- `abuse_confidence_score`
- `abuse_total_reports`
- `abuse_last_reported_at`
- `last_comment`
- `cf_rule_id`
- `cf_ban_mode`
- `cf_ban_expires_at`

Primary key:

```sql
PRIMARY KEY (ip, domain)
```

### `ip_cache` Table

Stores cached IP data:

- reverse DNS;
- reverse DNS check time;
- JSON from AbuseIPDB `check`;
- AbuseIPDB check time;
- ASN;
- `usageType`;
- `abuseConfidenceScore`;
- `totalReports`;
- `lastReportedAt`;
- `countryCode`;
- flags `is_whitelisted`, `is_public`, `is_tor`.

---

## Running

```bash
python3 abuse_reporter.py
```

On startup, the script reads the config from `.env` or from the path specified in `ABUSE_REPORTER_ENV_FILE`.

---

## systemd

### Example unit file

`/etc/systemd/system/abuse-reporter.service`

```ini
[Unit]
Description=Abuse Reporter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/abuse-reporter
EnvironmentFile=/opt/abuse-reporter/.env
ExecStart=/usr/bin/python3 /opt/abuse-reporter/abuse_reporter.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Management Commands

```bash
systemctl daemon-reload
systemctl enable --now abuse-reporter
systemctl status abuse-reporter
journalctl -u abuse-reporter -f
```

---

## Limitations and Notes

- On first run, if `state_file` does not exist, the script will process the log from the beginning of the current file.
- If `state_file` is corrupted and cannot be parsed as a number, the position will be reset to `0`.
- If the log was rotated and the previous position is larger than the new file size, reading will start from the beginning of the new file.
- With aggressive rotation between cycles, some lines may be lost.
- Reverse DNS and AbuseIPDB `check` are cached, but they still add network latency.
- Reverse DNS whitelisting is not strict search engine bot verification.
- A temporary Cloudflare ban is removed only if the record has a `cf_rule_id` or if it can be found again via the API.
- If `SITES_JSON` is empty or malformed, the script simply will not enter the working loop.

---

## License

This project is distributed under the terms of the MIT License. See the `LICENSE` file for details.