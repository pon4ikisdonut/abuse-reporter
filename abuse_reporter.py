#!/usr/bin/env python3

import ipaddress
import json
import os
import re
import socket
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

ABUSE_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"
CF_API_TOKEN = "YOUR_CLOUDFLARE_API_TOKEN_HERE"

SITES = [
    {
        "domain": "example1.com",
        "log_file": "/var/log/nginx/example1_access.log",
        "state_file": "/tmp/example1_abuse_last_pos.txt",
        "cf_zone_id": "YOUR_CLOUDFLARE_ZONE_ID_1",
    },
    {
        "domain": "example2.com",
        "log_file": "/var/log/nginx/example2_access.log",
        "state_file": "/tmp/example2_abuse_last_pos.txt",
        "cf_zone_id": "YOUR_CLOUDFLARE_ZONE_ID_2",
    },
]

DB_FILE = "/var/db/abuse_reporter.db"
CHECK_INTERVAL_SECONDS = 60
ABUSE_CHECK_MAX_AGE_DAYS = 90
ABUSE_REPORT_CATEGORIES = "15,21"
ABUSE_REQUEST_TIMEOUT = 15
ABUSE_COMMENT_MAX_LEN = 1024
REVERSE_DNS_CACHE_HOURS = 72
ABUSE_CHECK_CACHE_HOURS = 24
ABUSE_MIN_REQUEST_INTERVAL_SECONDS = 2.0
ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS = 2.0
ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS = 15.0
PROCESS_WORKERS = 2
SQLITE_TIMEOUT = 30

BAD_PATTERNS = [
    r"\.env", r"\.env\.local", r"\.env\.bak", r"\.env\.production",
    r"\.git/config", r"\.git/HEAD", r"\.git\b", r"\.svn/", r"\.hg/",
    r"secrets\.json", r"credentials\.json", r"config\.php", r"database\.php",
    r"\.bak", r"\.sql", r"\.sql\.gz", r"\.sqlite", r"dump\.sql", r"backup\.zip",
    r"www\.zip", r"site\.tar\.gz", r"docker-compose\.ya?ml", r"docker-compose\.override\.ya?ml",
    r"\.npmrc", r"composer\.json", r"package-lock\.json", r"sftp-config\.json",
    r"\.aws/credentials", r"\.aws\b", r"\.docker/config\.json", r"id_rsa", r"id_dsa",
    r"\.ssh/", r"\.pem$", r"\.key$", r"\.htpasswd", r"\.htaccess", r"\.DS_Store",
    r"\.idea/", r"\.vscode/", r"web\.config", r"crossdomain\.xml",
    r"wp-login\.php", r"wp-admin", r"wp-json", r"wp-content/uploads/.*\.php",
    r"xmlrpc\.php", r"phpinfo", r"phpmyadmin", r"adminer\.php", r"install\.php",
    r"setup\.php", r"debug\.php", r"test\.php", r"eval-stdin\.php", r"shell\.php",
    r"cmd\.php", r"actuator/(health|env|gateway)", r"vendor/phpunit", r"xdebug",
    r"joomla", r"drupal", r"/console/", r"/telescope", r"/_ignition/execute-solution",
    r"/manager/html", r"/solr/", r"/jenkins/", r"/elmah\.axd", r"/trace\.axd",
    r"/HNAP1", r"/cgi-bin/", r"/server-status", r"/metrics\b", r"/api/v1/pods",
    r"/\.well-known/(?!security\.txt)",
    r"\.\./", r"%2e%2e", r"%00", r"/etc/passwd", r"boot\.ini", r"win\.ini",
    r"union(\s|%20)+select", r"select.+from", r"information_schema",
    r"\bsleep\(\s*\d+\s*\)", r"\bbenchmark\(", r"or\s+1=1", r"<script",
    r"base64_decode", r"\bexec\(", r"cmd=", r"\bwget\b", r"\bcurl\b.*http",
    r"\$\{jndi:", r"log4j",
]

COMPILED_PATTERNS = [(p, re.compile(p, re.IGNORECASE)) for p in BAD_PATTERNS]

LOG_PATTERN = re.compile(
    r'^(?P<ip>[\w\.\:]+)\s+-\s+-\s+\[(?P<date>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<url>[^\s"]+)[^"]*"\s+(?P<status>\d+)'
)

WHITE_LIST_IPS = {
    "127.0.0.1",
    "::1",
}

WHITE_LIST_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

WHITE_LIST_ASNS = {
    # "AS15169",
    # "AS32934",
    # "AS8075",
}

WHITE_LIST_HOSTNAME_PATTERNS = [
    r"\.googlebot\.com$",
    r"\.google\.com$",
    r"\.search\.msn\.com$",
    r"\.bing\.com$",
    r"\.yandex\.ru$",
    r"\.yandex\.net$",
    r"\.crawl\.baidu\.com$",
]

COMPILED_HOSTNAME_PATTERNS = [re.compile(p, re.IGNORECASE) for p in WHITE_LIST_HOSTNAME_PATTERNS]

thread_local = threading.local()
rate_limit_lock = threading.Lock()
next_abuse_request_at = {}
run_cache_lock = threading.Lock()
report_submit_lock = threading.Lock()
run_reverse_cache = {}
run_abuse_cache = {}


class AbuseIPDBRateLimitError(Exception):
    pass


class SkipIP(Exception):
    def __init__(self, reason, abuse_meta=None):
        super().__init__(reason)
        self.reason = reason
        self.abuse_meta = abuse_meta or {}



def now_utc() -> datetime:
    return datetime.now(timezone.utc)



def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()



def parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str)
    except Exception:
        return None



def get_db_conn():
    conn = sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn



def truncate_comment(text: str, max_len: int = ABUSE_COMMENT_MAX_LEN) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."



def find_triggered_patterns(url):
    return [p for p, rx in COMPILED_PATTERNS if rx.search(url)]



def init_db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reported_ips (
            ip TEXT,
            domain TEXT,
            reported_at TEXT,
            cf_banned INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            abuse_confidence_score INTEGER,
            abuse_total_reports INTEGER,
            abuse_last_reported_at TEXT,
            last_comment TEXT,
            PRIMARY KEY (ip, domain)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            reverse_hostname TEXT,
            reverse_checked_at TEXT,
            abuse_json TEXT,
            abuse_checked_at TEXT,
            asn TEXT,
            usage_type TEXT,
            abuse_confidence_score INTEGER,
            total_reports INTEGER,
            last_reported_at TEXT,
            country_code TEXT,
            is_whitelisted INTEGER,
            is_public INTEGER,
            is_tor INTEGER
        )
    """)
    conn.commit()
    conn.close()



def is_ip_in_local_db(ip, domain):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM reported_ips WHERE ip = ? AND domain = ?", (ip, domain))
    row = cursor.fetchone()
    conn.close()
    return row is not None



def save_ip_to_db(ip, domain, first_seen, last_seen, cf_banned=0, abuse_meta=None, last_comment=None):
    abuse_meta = abuse_meta or {}
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO reported_ips
           (ip, domain, reported_at, cf_banned, first_seen, last_seen,
            abuse_confidence_score, abuse_total_reports, abuse_last_reported_at, last_comment)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            ip,
            domain,
            to_iso(now_utc()),
            cf_banned,
            first_seen,
            last_seen,
            abuse_meta.get("abuseConfidenceScore"),
            abuse_meta.get("totalReports"),
            abuse_meta.get("lastReportedAt"),
            last_comment,
        )
    )
    conn.commit()
    conn.close()



def get_cached_ip_row(ip):
    conn = get_db_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ip_cache WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None



def upsert_ip_cache(ip, **fields):
    existing = get_cached_ip_row(ip) or {"ip": ip}
    existing.update(fields)

    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO ip_cache
           (ip, reverse_hostname, reverse_checked_at, abuse_json, abuse_checked_at, asn,
            usage_type, abuse_confidence_score, total_reports, last_reported_at,
            country_code, is_whitelisted, is_public, is_tor)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            ip,
            existing.get("reverse_hostname"),
            existing.get("reverse_checked_at"),
            existing.get("abuse_json"),
            existing.get("abuse_checked_at"),
            existing.get("asn"),
            existing.get("usage_type"),
            existing.get("abuse_confidence_score"),
            existing.get("total_reports"),
            existing.get("last_reported_at"),
            existing.get("country_code"),
            existing.get("is_whitelisted"),
            existing.get("is_public"),
            existing.get("is_tor"),
        )
    )
    conn.commit()
    conn.close()



def parse_nginx_date(date_str):
    try:
        dt = datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        return date_str



def normalize_ip(ip):
    return str(ipaddress.ip_address(ip))



def ip_in_cidrs(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in ipaddress.ip_network(cidr, strict=False) for cidr in WHITE_LIST_CIDRS)
    except ValueError:
        return False



def is_private_or_reserved(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any([
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_link_local,
            ip_obj.is_multicast,
            ip_obj.is_reserved,
            ip_obj.is_unspecified,
        ])
    except ValueError:
        return True



def hostname_is_whitelisted(hostname):
    if not hostname:
        return False
    return any(rx.search(hostname) for rx in COMPILED_HOSTNAME_PATTERNS)



def get_reverse_hostname(ip):
    with run_cache_lock:
        cached = run_reverse_cache.get(ip)
        if cached:
            return cached

    db_row = get_cached_ip_row(ip)
    checked_at = parse_iso(db_row.get("reverse_checked_at")) if db_row else None
    if db_row and checked_at and now_utc() - checked_at < timedelta(hours=REVERSE_DNS_CACHE_HOURS):
        hostname = db_row.get("reverse_hostname")
        with run_cache_lock:
            run_reverse_cache[ip] = hostname
        return hostname

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        hostname = host.rstrip(".").lower()
    except Exception:
        hostname = None

    upsert_ip_cache(ip, reverse_hostname=hostname, reverse_checked_at=to_iso(now_utc()))
    with run_cache_lock:
        run_reverse_cache[ip] = hostname
    return hostname



def get_http_session():
    sess = getattr(thread_local, "session", None)
    if sess is None:
        sess = requests.Session()
        sess.headers.update({"Accept": "application/json", "Key": ABUSE_API_KEY})
        thread_local.session = sess
    return sess



def acquire_abuse_slot(slot_name="default", min_interval=ABUSE_MIN_REQUEST_INTERVAL_SECONDS):
    global next_abuse_request_at
    while True:
        with rate_limit_lock:
            now = time.time()
            current_next = next_abuse_request_at.get(slot_name, 0.0)
            allowed_at = max(now, current_next)
            wait = max(0.0, allowed_at - now)
            next_abuse_request_at[slot_name] = allowed_at + max(0.0, min_interval)
        if wait <= 0:
            return
        time.sleep(min(wait, 1.0))



def set_abuse_backoff(seconds, slot_name=None):
    global next_abuse_request_at
    with rate_limit_lock:
        backoff_until = time.time() + max(1, seconds)
        if slot_name is None:
            for key in list(next_abuse_request_at.keys()) or ["default", "check", "report"]:
                next_abuse_request_at[key] = max(next_abuse_request_at.get(key, 0.0), backoff_until)
        else:
            next_abuse_request_at[slot_name] = max(next_abuse_request_at.get(slot_name, 0.0), backoff_until)



def abuse_request(method, endpoint, *, params=None, data=None):
    if endpoint == "report":
        acquire_abuse_slot(slot_name="report", min_interval=ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS)
    elif endpoint == "check":
        acquire_abuse_slot(slot_name="check", min_interval=ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS)
    else:
        acquire_abuse_slot(slot_name="default", min_interval=ABUSE_MIN_REQUEST_INTERVAL_SECONDS)

    session = get_http_session()
    url = f"https://api.abuseipdb.com/api/v2/{endpoint}"
    try:
        response = session.request(
            method=method,
            url=url,
            params=params,
            data=data,
            timeout=ABUSE_REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        print(f"[!] Сетевая ошибка AbuseIPDB {endpoint}: {e}")
        return None

    if response.status_code == 429:
        retry_after = int(response.headers.get("Retry-After", "60"))
        print(
            f"[RATE][{endpoint}] limit={response.headers.get('X-RateLimit-Limit')} "
            f"remaining={response.headers.get('X-RateLimit-Remaining')} "
            f"reset={response.headers.get('X-RateLimit-Reset')} retry_after={retry_after}"
        )
        set_abuse_backoff(retry_after, slot_name=endpoint)
        raise AbuseIPDBRateLimitError(f"429 on {endpoint}")

    if response.status_code >= 400:
        try:
            payload = response.json()
        except Exception:
            payload = {"raw": response.text}
        print(f"[!] AbuseIPDB {endpoint} ошибка {response.status_code}: {payload}")
        return None

    try:
        return response.json()
    except ValueError:
        print(f"[!] AbuseIPDB {endpoint}: не удалось разобрать JSON")
        return None



def abuseipdb_check_ip(ip, max_age_days=ABUSE_CHECK_MAX_AGE_DAYS, verbose=False, use_cache=True):
    max_age_days = max(1, min(int(max_age_days), 365))
    cache_key = (ip, max_age_days, verbose)

    if use_cache:
        with run_cache_lock:
            if cache_key in run_abuse_cache:
                return run_abuse_cache[cache_key]

    if use_cache:
        db_row = get_cached_ip_row(ip)
        checked_at = parse_iso(db_row.get("abuse_checked_at")) if db_row else None
        if db_row and checked_at and now_utc() - checked_at < timedelta(hours=ABUSE_CHECK_CACHE_HOURS):
            abuse_json = db_row.get("abuse_json")
            if abuse_json:
                try:
                    data = json.loads(abuse_json)
                    with run_cache_lock:
                        run_abuse_cache[cache_key] = data
                    return data
                except Exception:
                    pass

    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    if verbose:
        params["verbose"] = ""

    payload = abuse_request("GET", "check", params=params)
    if payload is None:
        return None

    data = payload.get("data", {})
    upsert_ip_cache(
        ip,
        abuse_json=json.dumps(data, ensure_ascii=False),
        abuse_checked_at=to_iso(now_utc()),
        asn=(str(data.get("asn")).upper() if data.get("asn") else None),
        usage_type=data.get("usageType"),
        abuse_confidence_score=data.get("abuseConfidenceScore"),
        total_reports=data.get("totalReports"),
        last_reported_at=data.get("lastReportedAt"),
        country_code=data.get("countryCode"),
        is_whitelisted=1 if data.get("isWhitelisted") is True else 0 if data.get("isWhitelisted") is False else None,
        is_public=1 if data.get("isPublic") is True else 0 if data.get("isPublic") is False else None,
        is_tor=1 if data.get("isTor") is True else 0 if data.get("isTor") is False else None,
    )

    with run_cache_lock:
        run_abuse_cache[cache_key] = data
    return data



def should_skip_by_local_whitelist(ip):
    if ip in WHITE_LIST_IPS:
        return True, "WHITE_LIST_IPS"
    if ip_in_cidrs(ip):
        return True, "WHITE_LIST_CIDRS"
    if is_private_or_reserved(ip):
        return True, "private_or_reserved"

    hostname = get_reverse_hostname(ip)
    if hostname and hostname_is_whitelisted(hostname):
        return True, f"reverse_dns:{hostname}"

    return False, ""



def should_skip_by_abuse_metadata(abuse_data):
    if not abuse_data:
        return False, ""

    asn = str(abuse_data.get("asn")).upper() if abuse_data.get("asn") else None
    usage_type = abuse_data.get("usageType") or ""
    is_public = abuse_data.get("isPublic")

    if is_public is False:
        return True, "abuseipdb:is_public_false"
    if asn and asn in WHITE_LIST_ASNS:
        return True, f"asn:{asn}"
    if usage_type == "Search Engine Spider":
        return True, "abuseipdb:Search Engine Spider"

    return False, ""



def already_reported_by_me(abuse_data, report_tag):
    if abuse_data is None:
        return False, None

    for report in abuse_data.get("reports", []) or []:
        comment = report.get("comment", "") or ""
        if report_tag in comment:
            return True, report.get("reportedAt")

    return False, None



def build_report_comment(domain, data, report_tag):
    sampled_urls = ", ".join(sorted(data["urls"])[:5])
    triggers_str = ", ".join(sorted(data["triggers"])[:10])
    status_codes = ", ".join(sorted(map(str, data.get("statuses", set()))))
    methods = ", ".join(sorted(data.get("methods", set())))

    comment = (
        f"{report_tag}Automated report: malicious web probing against {domain}. "
        f"Methods: {methods}. HTTP statuses: {status_codes}. "
        f"Attempted URI(s): {sampled_urls}. Matched patterns: {triggers_str}. "
        f"First seen: {data['first_seen']}. Last seen: {data['last_seen']}. "
        f"Request count: {data['count']}."
    )
    return truncate_comment(comment)



def report_to_abuseipdb(ip, domain, data, report_tag):
    comment = build_report_comment(domain, data, report_tag)
    payload = {
        "ip": ip,
        "categories": ABUSE_REPORT_CATEGORIES,
        "comment": comment,
        "timestamp": data["first_seen"],
    }

    with report_submit_lock:
        result = abuse_request("POST", "report", data=payload)

    if result is None:
        return False, comment, None

    resp_data = result.get("data", {})
    print(f"[+] AbuseIPDB: успешно отправлен репорт на {ip}, score={resp_data.get('abuseConfidenceScore')}")
    return True, comment, resp_data



def ban_in_cloudflare(ip, cf_zone_id):
    if not cf_zone_id or "YOUR_CLOUDFLARE_ZONE_ID" in cf_zone_id:
        print(f"[~] Cloudflare zone id не задан для IP {ip}, пропускаем бан.")
        return 0

    if not CF_API_TOKEN or CF_API_TOKEN == "YOUR_CLOUDFLARE_API_TOKEN_HERE":
        print(f"[~] CF_API_TOKEN не задан, пропускаем Cloudflare ban для {ip}.")
        return 0

    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/firewall/access_rules/rules"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
    }
    body = {
        "mode": "block",
        "configuration": {"target": "ip6" if ":" in ip else "ip", "value": ip},
        "notes": "Automated ban by abuse_reporter.py for malicious web probing",
    }

    try:
        response = requests.post(url, headers=headers, json=body, timeout=15)
        res_json = response.json()
        if response.status_code == 200 and res_json.get("success"):
            print(f"[+] Cloudflare: IP {ip} успешно забанен.")
            return 1
        if "already exists" in response.text.lower():
            print(f"[-] Cloudflare: IP {ip} уже находится в чёрном списке.")
            return 1
        print(f"[!] Cloudflare ошибка для {ip}: {response.status_code} - {response.text}")
        return 0
    except Exception as e:
        print(f"[!] Ошибка сети с Cloudflare для {ip}: {e}")
        return 0



def parse_logs(site):
    log_file = site["log_file"]
    state_file = site["state_file"]

    if not os.path.exists(log_file):
        print(f"[-] Лог-файл {log_file} не найден для {site['domain']}.")
        return {}

    last_pos = 0
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            try:
                last_pos = int(f.read().strip())
            except ValueError:
                last_pos = 0

    malicious_activity = {}

    with open(log_file, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        if last_pos > file_size:
            last_pos = 0
        f.seek(last_pos)

        for line in f:
            match = LOG_PATTERN.match(line)
            if not match:
                continue

            try:
                ip = normalize_ip(match.group("ip"))
            except ValueError:
                continue

            url = match.group("url")
            method = match.group("method")
            status = match.group("status")
            date_iso = parse_nginx_date(match.group("date"))
            triggered = find_triggered_patterns(url)

            if not triggered:
                continue

            if ip not in malicious_activity:
                malicious_activity[ip] = {
                    "count": 0,
                    "urls": set(),
                    "triggers": set(),
                    "methods": set(),
                    "statuses": set(),
                    "first_seen": date_iso,
                    "last_seen": date_iso,
                }

            entry = malicious_activity[ip]
            entry["count"] += 1
            entry["urls"].add(url)
            entry["triggers"].update(triggered)
            entry["methods"].add(method)
            entry["statuses"].add(status)
            entry["first_seen"] = min(entry["first_seen"], date_iso)
            entry["last_seen"] = max(entry["last_seen"], date_iso)

        with open(state_file, "w") as sf:
            sf.write(str(f.tell()))

    return malicious_activity



def process_ip(site, ip, data):
    domain = site["domain"]
    report_tag = f"[pon4ik-autoreporter] {domain} | "

    print(
        f"\n[*][{domain}] Обработка нарушителя: {ip} ({data['count']} запросов, "
        f"первая атака: {data['first_seen']}, последняя: {data['last_seen']})"
    )
    print(f"[*][{domain}] Сработавшие триггеры: {', '.join(sorted(data['triggers']))}")

    if is_ip_in_local_db(ip, domain):
        print(f"[~] {ip} уже есть в локальной БД для {domain}, пропускаем.")
        return

    local_skip, local_reason = should_skip_by_local_whitelist(ip)
    if local_skip:
        print(f"[~] {ip} whitelisted ({local_reason}), пропускаем.")
        return

    abuse_meta = abuseipdb_check_ip(ip, max_age_days=ABUSE_CHECK_MAX_AGE_DAYS, verbose=True, use_cache=True) or {}

    abuse_skip, abuse_reason = should_skip_by_abuse_metadata(abuse_meta)
    if abuse_skip:
        print(f"[~] {ip} whitelisted ({abuse_reason}), пропускаем.")
        return

    reported_already, reported_at = already_reported_by_me(abuse_meta, report_tag)
    if reported_already:
        print(f"[~] {ip} уже репортился этим тегом ранее ({reported_at}), повтор не нужен.")
        cf_status = ban_in_cloudflare(ip, site["cf_zone_id"])
        save_ip_to_db(
            ip,
            domain,
            data["first_seen"],
            data["last_seen"],
            cf_banned=cf_status,
            abuse_meta=abuse_meta,
            last_comment="SKIPPED: already reported by me",
        )
        return

    abuse_success, comment, report_meta = report_to_abuseipdb(ip, domain, data, report_tag)
    cf_status = ban_in_cloudflare(ip, site["cf_zone_id"])

    if abuse_success:
        combined_meta = abuse_meta or {}
        if report_meta:
            combined_meta = {**combined_meta, **report_meta}
        save_ip_to_db(
            ip,
            domain,
            data["first_seen"],
            data["last_seen"],
            cf_banned=cf_status,
            abuse_meta=combined_meta,
            last_comment=comment,
        )



def process_site(site):
    bad_ips = parse_logs(site)
    if not bad_ips:
        return

    workers = min(PROCESS_WORKERS, max(1, len(bad_ips)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(process_ip, site, ip, data) for ip, data in bad_ips.items()]
        for future in as_completed(futures):
            try:
                future.result()
            except AbuseIPDBRateLimitError as e:
                print(f"[!] Rate limit AbuseIPDB: {e}")
            except Exception as e:
                print(f"[!] Ошибка worker: {e}")



def main_loop():
    init_db()
    print(
        f"[~] Запуск в режиме 24/7, интервал проверки: {CHECK_INTERVAL_SECONDS} сек. "
        f"Сайтов: {len(SITES)}, workers: {PROCESS_WORKERS}, report_mode: serialized"
    )
    while True:
        for site in SITES:
            try:
                process_site(site)
            except Exception as e:
                print(f"[!] Необработанная ошибка при обработке {site['domain']}: {e}")
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n[~] Остановлено пользователем.")