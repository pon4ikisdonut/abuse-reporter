import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


ENV_FILE = Path(os.getenv("ABUSE_REPORTER_ENV_FILE", ".env")).expanduser().resolve()


def load_env(path: Path) -> None:
    """Load .env, with special support for readable multiline SITES_JSON."""
    if not path.exists():
        return

    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key == "SITES_JSON":
            candidate = value
            while True:
                try:
                    parsed = json.loads(candidate)
                except json.JSONDecodeError as exc:
                    if i >= len(lines):
                        raise ValueError(
                            f"Invalid multiline SITES_JSON in .env: {exc.msg} "
                            f"(line {exc.lineno}, column {exc.colno})"
                        ) from exc
                    candidate += lines[i].strip()
                    i += 1
                    continue
                if not isinstance(parsed, list):
                    raise ValueError("SITES_JSON must contain a JSON array")
                os.environ[key] = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
                break
            continue

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)

    os.environ.setdefault("ABUSE_REPORTER_ENV_FILE", str(path))


def prepare_environment() -> None:
    load_env(ENV_FILE)
    os.environ.setdefault("DB_FILE", str(ENV_FILE.parent / "data" / "abuse_reporter.db"))

    raw_sites = os.getenv("SITES_JSON")
    if not raw_sites:
        return

    sites = json.loads(raw_sites)
    for site in sites:
        if not isinstance(site, dict):
            continue
        for field in ("log_file", "state_file"):
            value = site.get(field)
            if value and not os.path.isabs(value):
                site[field] = str((ENV_FILE.parent / value).resolve())

    os.environ["SITES_JSON"] = json.dumps(sites, ensure_ascii=False, separators=(",", ":"))


def main() -> None:
    prepare_environment()

    # Reverse DNS can block independently of HTTP request timeouts.
    dns_timeout = float(os.getenv("DNS_TIMEOUT_SECONDS", "3"))
    socket.setdefaulttimeout(max(0.5, dns_timeout))

    import abuse_reporter as app

    # The previous wrapper introduced artificial 2s/check and 15s/report
    # delays. AbuseIPDB documents daily API limits and a 15-minute duplicate
    # restriction for the SAME IP, not a global 15s delay for every report.
    # Keep the limiter as a safety mechanism, but make it short enough that
    # worker concurrency is actually useful. The server still enforces its
    # own limits and 429 responses are handled by abuse_reporter.py.
    original_acquire_abuse_slot = app.acquire_abuse_slot
    fast_min_interval = max(0.0, float(os.getenv("ABUSE_WORKER_MIN_INTERVAL_SECONDS", "0.10")))

    def acquire_abuse_slot_fast(slot_name="default", min_interval=0.0):
        return original_acquire_abuse_slot(
            slot_name=slot_name,
            min_interval=min(fast_min_interval, max(0.0, float(min_interval))),
        )

    app.acquire_abuse_slot = acquire_abuse_slot_fast

    # SQLite is shared by many workers. Add an explicit busy timeout on every
    # worker connection so short write contention does not look like a hang.
    original_get_db_conn = app.get_db_conn

    def get_db_conn_safe():
        conn = original_get_db_conn()
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    app.get_db_conn = get_db_conn_safe

    def already_reported_anywhere(abuse_meta):
        reports = (abuse_meta or {}).get("reports") or []
        return bool(reports), reports[0].get("reportedAt") if reports else None

    def process_ip(site, ip, data):
        domain = site["domain"]
        report_tag = f"[pon4ik-autoreporter] {domain} | "
        print(
            f"\n[*][{domain}] Processing violator: {ip} "
            f"({data['count']} requests, first attack: {data['first_seen']}, last: {data['last_seen']})",
            flush=True,
        )
        print(f"[*][{domain}] Triggered patterns: {', '.join(sorted(data['triggers']))}", flush=True)

        local_skip, local_reason = app.should_skip_by_local_whitelist(ip)
        if local_skip:
            print(f"[~] {ip} whitelisted ({local_reason}), skipping.", flush=True)
            return

        print(f"[~][{domain}] {ip}: checking AbuseIPDB ({app.ABUSE_CHECK_MAX_AGE_DAYS}d)...", flush=True)
        abuse_meta = app.abuseipdb_check_ip(
            ip,
            max_age_days=app.ABUSE_CHECK_MAX_AGE_DAYS,
            verbose=True,
            use_cache=True,
        )
        if abuse_meta is None:
            print(f"[!] {ip}: AbuseIPDB check failed; refusing to submit a new report.", flush=True)
            return

        abuse_skip, abuse_reason = app.should_skip_by_abuse_metadata(abuse_meta)
        if abuse_skip:
            print(f"[~] {ip} whitelisted ({abuse_reason}), skipping.", flush=True)
            return

        has_report, reported_at = already_reported_anywhere(abuse_meta)
        if has_report:
            print(
                f"[~] {ip} already has an AbuseIPDB report in the last "
                f"{app.ABUSE_CHECK_MAX_AGE_DAYS} days ({reported_at}); no duplicate report will be submitted.",
                flush=True,
            )
            cf_status, cf_rule_id, cf_ban_mode, cf_ban_expires_at = app.ban_in_cloudflare(ip, site["cf_zone_id"])
            app.save_ip_to_db(ip, domain, data["first_seen"], data["last_seen"], cf_banned=cf_status, abuse_meta=abuse_meta, last_comment=f"SKIPPED: AbuseIPDB already has a report in the configured window ({reported_at})", cf_rule_id=cf_rule_id, cf_ban_mode=cf_ban_mode, cf_ban_expires_at=cf_ban_expires_at)
            return

        print(f"[~][{domain}] {ip}: no AbuseIPDB report found; submitting...", flush=True)
        abuse_success, comment, report_meta = app.report_to_abuseipdb(ip, domain, data, report_tag)
        cf_status, cf_rule_id, cf_ban_mode, cf_ban_expires_at = app.ban_in_cloudflare(ip, site["cf_zone_id"])

        if abuse_success:
            combined_meta = {**abuse_meta, **(report_meta or {})}
            app.save_ip_to_db(ip, domain, data["first_seen"], data["last_seen"], cf_banned=cf_status, abuse_meta=combined_meta, last_comment=comment, cf_rule_id=cf_rule_id, cf_ban_mode=cf_ban_mode, cf_ban_expires_at=cf_ban_expires_at)
        elif cf_status:
            app.save_ip_to_db(ip, domain, data["first_seen"], data["last_seen"], cf_banned=cf_status, abuse_meta=abuse_meta, last_comment="CF ban applied, AbuseIPDB report failed", cf_rule_id=cf_rule_id, cf_ban_mode=cf_ban_mode, cf_ban_expires_at=cf_ban_expires_at)

    app.process_ip = process_ip

    original_init_db = app.init_db

    def init_db_safe():
        os.makedirs(os.path.dirname(os.path.abspath(app.DB_FILE)), exist_ok=True)
        return original_init_db()

    app.init_db = init_db_safe

    def fast_main_loop():
        if not app.validate_sites_config():
            return

        app.init_db()
        workers = max(1, int(app.PROCESS_WORKERS))
        print(
            f"[~] Starting in 24/7 mode, check interval: {app.CHECK_INTERVAL_SECONDS} sec. "
            f"Sites: {len(app.SITES)}, shared workers: {workers}, "
            f"AbuseIPDB worker interval: {fast_min_interval:.2f}s, "
            f"cf_ban_mode: {app.CF_BAN_MODE}",
            flush=True,
        )

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="abuse-worker") as executor:
            while True:
                cycle_started = time.monotonic()
                app.cleanup_expired_cloudflare_bans()
                futures = []

                for site in app.SITES:
                    try:
                        bad_ips = app.parse_logs(site)
                        for ip, data in bad_ips.items():
                            futures.append(executor.submit(app.process_ip, site, ip, data))
                    except Exception as exc:
                        print(f"[!] Unhandled error while parsing {site['domain']}: {exc}", flush=True)

                if futures:
                    print(f"[~] Submitted {len(futures)} IP jobs to {workers} workers.", flush=True)

                completed = 0
                for future in as_completed(futures):
                    try:
                        future.result()
                    except app.AbuseIPDBRateLimitError as exc:
                        print(f"[!] Rate limit AbuseIPDB: {exc}", flush=True)
                    except Exception as exc:
                        print(f"[!] Error in worker: {exc}", flush=True)
                    completed += 1
                    if completed % max(1, workers) == 0 or completed == len(futures):
                        print(f"[~] Progress: {completed}/{len(futures)} IP jobs finished.", flush=True)

                elapsed = time.monotonic() - cycle_started
                sleep_for = max(0, app.CHECK_INTERVAL_SECONDS - elapsed)
                print(f"[~] Cycle finished in {elapsed:.1f}s; next check in {sleep_for:.1f}s.", flush=True)
                time.sleep(sleep_for)

    app.main_loop = fast_main_loop
    app.main_loop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[~] Stopped by user.")
