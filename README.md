# abuse-reporter

Automatic nginx access-log monitor that detects suspicious web probing, checks IPs in AbuseIPDB, reports new abuse, and optionally blocks offenders in Cloudflare.

## What changed

- **Windows support:** use `run.py` as the portable entry point. Relative paths are resolved from the `.env` directory, so the same configuration works on Windows, Linux and macOS.
- **Readable multiline `SITES_JSON`:** the `.env` loader accepts a normal JSON array spread across multiple lines instead of forcing everything into one unreadable line.
- **AbuseIPDB duplicate protection:** before every new report the program calls AbuseIPDB `check` with `maxAgeInDays=ABUSE_CHECK_MAX_AGE_DAYS` and `verbose=True`. If AbuseIPDB returns *any* report in that window, no new report is submitted. If the check itself fails, reporting fails closed and no new report is submitted.
- **The local SQLite DB no longer decides whether an AbuseIPDB report is a duplicate.** It remains useful for local state and Cloudflare-ban bookkeeping, while AbuseIPDB is the source of truth for the configured report window.
- **Portable DB default:** if `DB_FILE` is not set, the database is created under `data/abuse_reporter.db` next to `.env`.

## Requirements

Python 3.8+ and `requests`:

```bash
python -m pip install requests
```

## Configuration

Copy `.env.example` to `.env` and fill in your API keys.

The important part is now genuinely readable:

```dotenv
SITES_JSON=[
  {
    "domain": "example.com",
    "log_file": "logs/example_access.log",
    "state_file": "data/example_last_pos.txt",
    "cf_zone_id": "your_cloudflare_zone_id"
  }
]
```

Relative `log_file`, `state_file` and `DB_FILE` paths are portable. Absolute Windows paths such as `C:\\nginx\\logs\\access.log` are also supported by the normal Python path handling.

### AbuseIPDB duplicate window

```dotenv
ABUSE_CHECK_MAX_AGE_DAYS=90
```

For every candidate IP, `run.py` performs an AbuseIPDB `check` using this value as `maxAgeInDays`. Because the request uses `verbose=True`, the returned `reports` list represents reports in the requested window. The logic is:

1. AbuseIPDB check succeeds.
2. If the returned `reports` list is non-empty, **do not report the IP again**.
3. If the list is empty, submit the new report.
4. If the check cannot be completed, **do not submit** a new report (fail closed).

This is deliberately different from only looking for the reporter's own comment/tag: another AbuseIPDB user having reported the IP is enough to suppress a duplicate report inside the configured window.

## Running

### Windows

```powershell
py -m pip install requests
py run.py
```

Or:

```powershell
python run.py
```

### Linux/macOS

```bash
python3 -m pip install requests
python3 run.py
```

The original `abuse_reporter.py` remains the core application logic; `run.py` provides the portable configuration/runtime layer and the corrected AbuseIPDB duplicate-report policy.

## Detection and Cloudflare

The existing detector, nginx incremental parsing, CF-Connecting-IP support, SQLite cache, whitelist rules, AbuseIPDB rate limiting, and Cloudflare permanent/temporary bans are preserved.

Cloudflare banning is still performed after a report is skipped because an existing AbuseIPDB report does not mean the IP should stop being blocked locally. The existing whitelist and Cloudflare configuration therefore continue to apply.
