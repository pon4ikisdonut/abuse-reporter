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
from urllib.parse import unquote

import requests


def load_env_file(path: str = ".env"):
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                    value = value[1:-1]
                os.environ.setdefault(key, value)
    except Exception as e:
        print(f"[!] Error loading .env: {e}")


def env_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip()


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value.strip())
    except ValueError:
        print(f"[!] Incorrect value for {name}={value!r}, using {default}")
        return default


def env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value.strip())
    except ValueError:
        print(f"[!] Incorrect value for {name}={value!r}, using {default}")
        return default


def env_list(name: str, default=None):
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


def env_json(name: str, default):
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return json.loads(raw)
    except Exception as e:
        print(f"[!] Incorrect JSON in {name}: {e}")
        return default


def load_config():
    load_env_file(os.getenv("ABUSE_REPORTER_ENV_FILE", ".env"))
    config = {}
    config["ABUSE_API_KEY"] = env_str("ABUSE_API_KEY", "")
    config["CF_API_TOKEN"] = env_str("CF_API_TOKEN", "")
    config["SITES"] = env_json("SITES_JSON", [])
    config["DB_FILE"] = env_str("DB_FILE", "/var/db/abuse_reporter.db")
    config["CHECK_INTERVAL_SECONDS"] = env_int("CHECK_INTERVAL_SECONDS", 60)
    config["ABUSE_CHECK_MAX_AGE_DAYS"] = env_int("ABUSE_CHECK_MAX_AGE_DAYS", 90)
    config["ABUSE_REPORT_CATEGORIES"] = env_str("ABUSE_REPORT_CATEGORIES", "15,21")
    config["ABUSE_REQUEST_TIMEOUT"] = env_int("ABUSE_REQUEST_TIMEOUT", 15)
    config["ABUSE_COMMENT_MAX_LEN"] = env_int("ABUSE_COMMENT_MAX_LEN", 1024)
    config["REVERSE_DNS_CACHE_HOURS"] = env_int("REVERSE_DNS_CACHE_HOURS", 72)
    config["ABUSE_CHECK_CACHE_HOURS"] = env_int("ABUSE_CHECK_CACHE_HOURS", 24)
    config["ABUSE_MIN_REQUEST_INTERVAL_SECONDS"] = env_float("ABUSE_MIN_REQUEST_INTERVAL_SECONDS", 2.0)
    config["ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS"] = env_float("ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS", 2.0)
    config["ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS"] = env_float("ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS", 15.0)
    config["PROCESS_WORKERS"] = env_int("PROCESS_WORKERS", 2)
    config["SQLITE_TIMEOUT"] = env_int("SQLITE_TIMEOUT", 30)
    config["CF_BAN_MODE"] = env_str("CF_BAN_MODE", "permanent").lower()
    config["CF_TEMP_BAN_MINUTES"] = env_int("CF_TEMP_BAN_MINUTES", 60)
    config["CF_REQUEST_TIMEOUT"] = env_int("CF_REQUEST_TIMEOUT", 15)
    config["WHITE_LIST_IPS"] = set(env_list("WHITE_LIST_IPS", ["127.0.0.1", "::1"]))
    config["WHITE_LIST_CIDRS"] = env_list(
        "WHITE_LIST_CIDRS",
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ],
    )
    config["WHITE_LIST_ASNS"] = set(item.upper() for item in env_list("WHITE_LIST_ASNS", []))
    config["WHITE_LIST_HOSTNAME_PATTERNS"] = env_list(
        "WHITE_LIST_HOSTNAME_PATTERNS",
        [
            r"\.googlebot\.com$",
            r"\.google\.com$",
            r"\.search\.msn\.com$",
            r"\.bing\.com$",
            r"\.yandex\.ru$",
            r"\.yandex\.net$",
            r"\.crawl\.baidu\.com$",
        ],
    )
    return config


CONFIG = load_config()
ABUSE_API_KEY = CONFIG["ABUSE_API_KEY"]
CF_API_TOKEN = CONFIG["CF_API_TOKEN"]
SITES = CONFIG["SITES"]
DB_FILE = CONFIG["DB_FILE"]
CHECK_INTERVAL_SECONDS = CONFIG["CHECK_INTERVAL_SECONDS"]
ABUSE_CHECK_MAX_AGE_DAYS = CONFIG["ABUSE_CHECK_MAX_AGE_DAYS"]
ABUSE_REPORT_CATEGORIES = CONFIG["ABUSE_REPORT_CATEGORIES"]
ABUSE_REQUEST_TIMEOUT = CONFIG["ABUSE_REQUEST_TIMEOUT"]
ABUSE_COMMENT_MAX_LEN = CONFIG["ABUSE_COMMENT_MAX_LEN"]
REVERSE_DNS_CACHE_HOURS = CONFIG["REVERSE_DNS_CACHE_HOURS"]
ABUSE_CHECK_CACHE_HOURS = CONFIG["ABUSE_CHECK_CACHE_HOURS"]
ABUSE_MIN_REQUEST_INTERVAL_SECONDS = CONFIG["ABUSE_MIN_REQUEST_INTERVAL_SECONDS"]
ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS = CONFIG["ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS"]
ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS = CONFIG["ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS"]
PROCESS_WORKERS = CONFIG["PROCESS_WORKERS"]
SQLITE_TIMEOUT = CONFIG["SQLITE_TIMEOUT"]
CF_BAN_MODE = CONFIG["CF_BAN_MODE"]
CF_TEMP_BAN_MINUTES = CONFIG["CF_TEMP_BAN_MINUTES"]
CF_REQUEST_TIMEOUT = CONFIG["CF_REQUEST_TIMEOUT"]
WHITE_LIST_IPS = CONFIG["WHITE_LIST_IPS"]
WHITE_LIST_CIDRS = CONFIG["WHITE_LIST_CIDRS"]
WHITE_LIST_ASNS = CONFIG["WHITE_LIST_ASNS"]
WHITE_LIST_HOSTNAME_PATTERNS = CONFIG["WHITE_LIST_HOSTNAME_PATTERNS"]

PATTERN_RULES = [
    {"name": r"\\.env", "pattern": r"\.env", "status_gated": False},
    {"name": r"\\.env\\.local", "pattern": r"\.env\.local", "status_gated": False},
    {"name": r"\\.env\\.bak", "pattern": r"\.env\.bak", "status_gated": False},
    {"name": r"\\.env\\.production", "pattern": r"\.env\.production", "status_gated": False},
    {"name": r"\\.git/config", "pattern": r"\.git/config", "status_gated": False},
    {"name": r"\\.git/HEAD", "pattern": r"\.git/HEAD", "status_gated": False},
    {"name": r"\\.git\\b", "pattern": r"\.git\b", "status_gated": False},
    {"name": r"\\.svn/", "pattern": r"\.svn/", "status_gated": False},
    {"name": r"\\.hg/", "pattern": r"\.hg/", "status_gated": False},
    {"name": r"secrets\\.json", "pattern": r"secrets\.json", "status_gated": False},
    {"name": r"credentials\\.json", "pattern": r"credentials\.json", "status_gated": False},
    {"name": r"config\\.php", "pattern": r"config\.php", "status_gated": False},
    {"name": r"database\\.php", "pattern": r"database\.php", "status_gated": False},
    {"name": r"\\.bak", "pattern": r"\.bak", "status_gated": False},
    {"name": r"\\.sql", "pattern": r"\.sql", "status_gated": False},
    {"name": r"\\.sql\\.gz", "pattern": r"\.sql\.gz", "status_gated": False},
    {"name": r"\\.sqlite", "pattern": r"\.sqlite", "status_gated": False},
    {"name": r"dump\\.sql", "pattern": r"dump\.sql", "status_gated": False},
    {"name": r"backup\\.zip", "pattern": r"backup\.zip", "status_gated": False},
    {"name": r"www\\.zip", "pattern": r"www\.zip", "status_gated": False},
    {"name": r"site\\.tar\\.gz", "pattern": r"site\.tar\.gz", "status_gated": False},
    {"name": r"docker-compose\\.ya?ml", "pattern": r"docker-compose\.ya?ml", "status_gated": False},
    {"name": r"docker-compose\\.override\\.ya?ml", "pattern": r"docker-compose\.override\.ya?ml", "status_gated": False},
    {"name": r"\\.npmrc", "pattern": r"\.npmrc", "status_gated": False},
    {"name": r"composer\\.json", "pattern": r"composer\.json", "status_gated": False},
    {"name": r"package-lock\\.json", "pattern": r"package-lock\.json", "status_gated": False},
    {"name": r"sftp-config\\.json", "pattern": r"sftp-config\.json", "status_gated": False},
    {"name": r"\\.aws/credentials", "pattern": r"\.aws/credentials", "status_gated": False},
    {"name": r"\\.aws\\b", "pattern": r"\.aws\b", "status_gated": False},
    {"name": r"\\.docker/config\\.json", "pattern": r"\.docker/config\.json", "status_gated": False},
    {"name": r"id_rsa", "pattern": r"id_rsa", "status_gated": False},
    {"name": r"id_dsa", "pattern": r"id_dsa", "status_gated": False},
    {"name": r"\\.ssh/", "pattern": r"\.ssh/", "status_gated": False},
    {"name": r"\\.pem$", "pattern": r"\.pem$", "status_gated": False},
    {"name": r"\\.key$", "pattern": r"\.key$", "status_gated": False},
    {"name": r"\\.htpasswd", "pattern": r"\.htpasswd", "status_gated": False},
    {"name": r"\\.htaccess", "pattern": r"\.htaccess", "status_gated": False},
    {"name": r"\\.DS_Store", "pattern": r"\.DS_Store", "status_gated": False},
    {"name": r"\\.idea/", "pattern": r"\.idea/", "status_gated": False},
    {"name": r"\\.vscode/", "pattern": r"\.vscode/", "status_gated": False},
    {"name": r"web\\.config", "pattern": r"web\.config", "status_gated": False},
    {"name": r"crossdomain\\.xml", "pattern": r"crossdomain\.xml", "status_gated": False},
    {"name": r"wp-login\\.php", "pattern": r"wp-login\.php", "status_gated": False},
    {"name": r"wp-admin", "pattern": r"wp-admin", "status_gated": False},
    {"name": r"wp-json", "pattern": r"wp-json", "status_gated": False},
    {"name": r"wp-content/uploads/.*\\.php", "pattern": r"wp-content/uploads/.*\.php", "status_gated": False},
    {"name": r"xmlrpc\\.php", "pattern": r"xmlrpc\.php", "status_gated": False},
    {"name": r"phpinfo", "pattern": r"phpinfo", "status_gated": False},
    {"name": r"phpmyadmin", "pattern": r"phpmyadmin", "status_gated": False},
    {"name": r"adminer\\.php", "pattern": r"adminer\.php", "status_gated": False},
    {"name": r"install\\.php", "pattern": r"install\.php", "status_gated": False},
    {"name": r"setup\\.php", "pattern": r"setup\.php", "status_gated": False},
    {"name": r"debug\\.php", "pattern": r"debug\.php", "status_gated": False},
    {"name": r"test\\.php", "pattern": r"test\.php", "status_gated": False},
    {"name": r"eval-stdin\\.php", "pattern": r"eval-stdin\.php", "status_gated": False},
    {"name": r"shell\\.php", "pattern": r"shell\.php", "status_gated": False},
    {"name": r"cmd\\.php", "pattern": r"cmd\.php", "status_gated": False},
    {"name": r"actuator/(health|env|gateway)", "pattern": r"actuator/(health|env|gateway)", "status_gated": False},
    {"name": r"vendor/phpunit", "pattern": r"vendor/phpunit", "status_gated": False},
    {"name": r"xdebug", "pattern": r"xdebug", "status_gated": False},
    {"name": r"joomla", "pattern": r"joomla", "status_gated": False},
    {"name": r"drupal", "pattern": r"drupal", "status_gated": False},
    {"name": r"/console/", "pattern": r"/console/", "status_gated": False},
    {"name": r"/telescope", "pattern": r"/telescope", "status_gated": False},
    {"name": r"/_ignition/execute-solution", "pattern": r"/_ignition/execute-solution", "status_gated": False},
    {"name": r"/manager/html", "pattern": r"/manager/html", "status_gated": False},
    {"name": r"/solr/", "pattern": r"/solr/", "status_gated": False},
    {"name": r"/jenkins/", "pattern": r"/jenkins/", "status_gated": False},
    {"name": r"/elmah\\.axd", "pattern": r"/elmah\.axd", "status_gated": False},
    {"name": r"/trace\\.axd", "pattern": r"/trace\.axd", "status_gated": False},
    {"name": r"/HNAP1", "pattern": r"/HNAP1", "status_gated": False},
    {"name": r"/cgi-bin/", "pattern": r"/cgi-bin/", "status_gated": False},
    {"name": r"/server-status", "pattern": r"/server-status", "status_gated": False},
    {"name": r"/metrics\\b", "pattern": r"/metrics\b", "status_gated": False},
    {"name": r"/api/v1/pods", "pattern": r"/api/v1/pods", "status_gated": False},
    {"name": r"/\\.well-known/(?!security\\.txt)", "pattern": r"/\.well-known/(?!security\.txt)", "status_gated": False},
    {"name": r"\\.\\./", "pattern": r"\.\./", "status_gated": False},
    {"name": r"%2e%2e", "pattern": r"%2e%2e", "status_gated": False},
    {"name": r"%00", "pattern": r"%00", "status_gated": False},
    {"name": r"/etc/passwd", "pattern": r"/etc/passwd", "status_gated": False},
    {"name": r"boot\\.ini", "pattern": r"boot\.ini", "status_gated": False},
    {"name": r"win\\.ini", "pattern": r"win\.ini", "status_gated": False},
    {"name": r"union(\\s|%20|\\+)+select", "pattern": r"union(\s|%20|\+)+select", "status_gated": False},
    {"name": r"select(?:\\s|%20|\\+)+[\\w\\*\\.,()'\"-]{1,120}(?:\\s|%20|\\+)+from", "pattern": r"select(?:\s|%20|\+)+[\w\*\.,()'\"-]{1,120}(?:\s|%20|\+)+from", "status_gated": True},
    {"name": r"information_schema", "pattern": r"information_schema", "status_gated": False},
    {"name": r"\\bsleep\\(\\s*\\d+\\s*\\)", "pattern": r"\bsleep\(\s*\d+\s*\)", "status_gated": False},
    {"name": r"\\bbenchmark\\(", "pattern": r"\bbenchmark\(", "status_gated": False},
    {"name": r"or\\s+1=1", "pattern": r"or\s+1=1", "status_gated": False},
    {"name": r"<script", "pattern": r"<script", "status_gated": False},
    {"name": r"base64_decode", "pattern": r"base64_decode", "status_gated": False},
    {"name": r"\\bexec\\(", "pattern": r"\bexec\(", "status_gated": False},
    {"name": r"cmd=", "pattern": r"cmd=", "status_gated": False},
    {"name": r"\\bwget\\b", "pattern": r"\bwget\b", "status_gated": False},
    {"name": r"\\bcurl\\b.*http", "pattern": r"\bcurl\b.*http", "status_gated": False},
    {"name": r"\\$\\{jndi:", "pattern": r"\$\{jndi:", "status_gated": False},
    {"name": r"log4j", "pattern": r"log4j", "status_gated": False},
]

COMPILED_PATTERNS = [(rule["name"], re.compile(rule["pattern"], re.IGNORECASE), rule["status_gated"]) for rule in PATTERN_RULES]
COMPILED_HOSTNAME_PATTERNS = [re.compile(p, re.IGNORECASE) for p in WHITE_LIST_HOSTNAME_PATTERNS]
LOG_PATTERN = re.compile(r'^(?P<ip>[^\s]+)\s+-\s+-\s+\[(?P<date>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<url>[^\s"]+)[^"]*"\s+(?P<status>\d+)')
CF_CONNECTING_IP_PATTERNS = [
    re.compile(r'(?:^|[\s\"\[])(?:cf_connecting_ip|http_cf_connecting_ip|cf-connecting-ip|CF-Connecting-IP)[=:\s\"]+(?P<ip>[0-9a-fA-F:\.]+)'),
    re.compile(r'"(?:cf_connecting_ip|http_cf_connecting_ip|cf-connecting-ip|CF-Connecting-IP)"\s*:\s*"(?P<ip>[0-9a-fA-F:\.]+)"'),
]
SUSPICIOUS_HTTP_STATUSES = {
    "400", "401", "403", "404", "405", "406", "408", "409", "410", "412", "414", "418",
    "421", "429", "444", "494", "495", "496", "497", "499", "500", "501", "502", "503",
    "504", "520", "521", "522", "523", "524", "525", "526",
}
thread_local = threading.local()
rate_limit_lock = threading.Lock()
next_abuse_request_at = {}
run_cache_lock = threading.Lock()
report_submit_lock = threading.Lock()
run_reverse_cache = {}
run_abuse_cache = {}


class AbuseIPDBRateLimitError(Exception):
    pass


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


def url_variants(url: str):
    variants = {url}
    try:
        variants.add(unquote(url))
    except Exception:
        pass
    return list(variants)


def find_triggered_patterns(url, status):
    triggered = []
    variants = url_variants(url)
    for name, rx, status_gated in COMPILED_PATTERNS:
        if status_gated and status not in SUSPICIOUS_HTTP_STATUSES:
            continue
        if any(rx.search(variant) for variant in variants):
            triggered.append(name)
    return triggered


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
            cf_rule_id TEXT,
            cf_ban_mode TEXT,
            cf_ban_expires_at TEXT,
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
    existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(reported_ips)")}
    for column, ddl in [
        ("cf_rule_id", "ALTER TABLE reported_ips ADD COLUMN cf_rule_id TEXT"),
        ("cf_ban_mode", "ALTER TABLE reported_ips ADD COLUMN cf_ban_mode TEXT"),
        ("cf_ban_expires_at", "ALTER TABLE reported_ips ADD COLUMN cf_ban_expires_at TEXT"),
    ]:
        if column not in existing_cols:
            cursor.execute(ddl)
    conn.commit()
    conn.close()


def get_reported_ip_row(ip, domain):
    conn = get_db_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reported_ips WHERE ip = ? AND domain = ?", (ip, domain))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def save_ip_to_db(ip, domain, first_seen, last_seen, cf_banned=0, abuse_meta=None, last_comment=None, cf_rule_id=None, cf_ban_mode=None, cf_ban_expires_at=None):
    abuse_meta = abuse_meta or {}
    prev = get_reported_ip_row(ip, domain) or {}
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO reported_ips
           (ip, domain, reported_at, cf_banned, first_seen, last_seen,
            abuse_confidence_score, abuse_total_reports, abuse_last_reported_at, last_comment,
            cf_rule_id, cf_ban_mode, cf_ban_expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
            cf_rule_id if cf_rule_id is not None else prev.get("cf_rule_id"),
            cf_ban_mode if cf_ban_mode is not None else prev.get("cf_ban_mode"),
            cf_ban_expires_at if cf_ban_expires_at is not None else prev.get("cf_ban_expires_at"),
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
        response = session.request(method=method, url=url, params=params, data=data, timeout=ABUSE_REQUEST_TIMEOUT)
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
    payload = {"ip": ip, "categories": ABUSE_REPORT_CATEGORIES, "comment": comment, "timestamp": data["first_seen"]}
    with report_submit_lock:
        result = abuse_request("POST", "report", data=payload)
    if result is None:
        return False, comment, None
    resp_data = result.get("data", {})
    print(f"[+] AbuseIPDB: Successfully submitted report for {ip}, score={resp_data.get('abuseConfidenceScore')}")
    return True, comment, resp_data


def get_cf_session():
    sess = getattr(thread_local, "cf_session", None)
    if sess is None:
        sess = requests.Session()
        sess.headers.update({"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"})
        thread_local.cf_session = sess
    return sess


def cf_request(method, url, **kwargs):
    try:
        return get_cf_session().request(method=method, url=url, timeout=CF_REQUEST_TIMEOUT, **kwargs)
    except requests.RequestException as e:
        print(f"[!] Network error with Cloudflare: {e}")
        return None


def find_cloudflare_rule(ip, cf_zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/firewall/access_rules/rules"
    params = {"configuration.target": "ip6" if ":" in ip else "ip", "configuration.value": ip, "page": 1, "per_page": 1}
    response = cf_request("GET", url, params=params)
    if response is None:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if response.status_code != 200 or not payload.get("success"):
        return None
    result = payload.get("result") or []
    return result[0] if result else None


def delete_cloudflare_rule(cf_zone_id, rule_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/firewall/access_rules/rules/{rule_id}"
    response = cf_request("DELETE", url)
    if response is None:
        return False
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if response.status_code == 200 and payload.get("success"):
        return True
    print(f"[!] Cloudflare delete error {response.status_code}: {payload or response.text}")
    return False


def ban_in_cloudflare(ip, cf_zone_id):
    if not cf_zone_id:
        print(f"[~] Cloudflare zone id not set for IP {ip}, skipping ban.")
        return 0, None, None, None
    if not CF_API_TOKEN:
        print(f"[~] CF_API_TOKEN not set, skipping Cloudflare ban for {ip}.")
        return 0, None, None, None
    if CF_BAN_MODE not in {"permanent", "temporary"}:
        print(f"[~] Incorrect CF_BAN_MODE={CF_BAN_MODE}, using permanent.")
    effective_mode = CF_BAN_MODE if CF_BAN_MODE in {"permanent", "temporary"} else "permanent"
    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/firewall/access_rules/rules"
    body = {
        "mode": "block",
        "configuration": {"target": "ip6" if ":" in ip else "ip", "value": ip},
        "notes": "Automated ban by abuse_reporter.py for malicious web probing",
    }
    response = cf_request("POST", url, json=body)
    if response is None:
        return 0, None, None, None
    try:
        res_json = response.json()
    except ValueError:
        res_json = {}
    if response.status_code == 200 and res_json.get("success"):
        result = res_json.get("result") or {}
        rule_id = result.get("id")
        expires_at = None
        if effective_mode == "temporary":
            expires_at = to_iso(now_utc() + timedelta(minutes=max(1, CF_TEMP_BAN_MINUTES)))
            print(f"[+] Cloudflare: IP {ip} successfully banned temporarily until {expires_at}.")
        else:
            print(f"[+] Cloudflare: IP {ip} successfully banned permanently.")
        return 1, rule_id, effective_mode, expires_at
    if "already exists" in response.text.lower():
        existing_rule = find_cloudflare_rule(ip, cf_zone_id)
        existing_rule_id = existing_rule.get("id") if existing_rule else None
        expires_at = to_iso(now_utc() + timedelta(minutes=max(1, CF_TEMP_BAN_MINUTES))) if effective_mode == "temporary" else None
        print(f"[-] Cloudflare: IP {ip} is already in the blacklist.")
        return 1, existing_rule_id, effective_mode, expires_at
    print(f"[!] Cloudflare error for {ip}: {response.status_code} - {response.text}")
    return 0, None, None, None


def cleanup_expired_cloudflare_bans():
    if CF_BAN_MODE != "temporary":
        return
    domain_to_zone = {site["domain"]: site.get("cf_zone_id") for site in SITES}
    conn = get_db_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT ip, domain, cf_rule_id, cf_ban_expires_at FROM reported_ips WHERE cf_ban_mode = 'temporary' AND cf_ban_expires_at IS NOT NULL AND cf_banned = 1")
    rows = [dict(row) for row in cursor.fetchall()]
    for row in rows:
        expires_at = parse_iso(row.get("cf_ban_expires_at"))
        if not expires_at or expires_at > now_utc():
            continue
        rule_id = row.get("cf_rule_id")
        zone_id = domain_to_zone.get(row.get("domain"))
        if not zone_id:
            continue
        if not rule_id:
            existing = find_cloudflare_rule(row["ip"], zone_id)
            rule_id = existing.get("id") if existing else None
        if rule_id and delete_cloudflare_rule(zone_id, rule_id):
            cursor.execute("UPDATE reported_ips SET cf_banned = 0, cf_rule_id = NULL, cf_ban_expires_at = NULL WHERE ip = ? AND domain = ?", (row["ip"], row["domain"]))
            print(f"[+] Cloudflare: temporary ban removed for {row['ip']} ({row['domain']}).")
    conn.commit()
    conn.close()


def extract_client_ip(line, fallback_ip):
    candidates = []
    for rx in CF_CONNECTING_IP_PATTERNS:
        m = rx.search(line)
        if m:
            candidates.append(m.group("ip"))
    candidates.append(fallback_ip)
    for candidate in candidates:
        try:
            return normalize_ip(candidate.strip().strip('"').strip("'"))
        except Exception:
            continue
    raise ValueError("client ip not found")


def parse_logs(site):
    log_file = site["log_file"]
    state_file = site["state_file"]
    if not os.path.exists(log_file):
        print(f"[-] Log file {log_file} not found for {site['domain']}.")
        return {}
    last_pos = 0
    if os.path.exists(state_file):
        with open(state_file, "r", encoding="utf-8") as f:
            try:
                last_pos = int(f.read().strip())
            except ValueError:
                last_pos = 0
    malicious_activity = {}
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
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
                ip = extract_client_ip(line, match.group("ip"))
            except ValueError:
                continue
            url = match.group("url")
            method = match.group("method")
            status = match.group("status")
            date_iso = parse_nginx_date(match.group("date"))
            triggered = find_triggered_patterns(url, status)
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
        with open(state_file, "w", encoding="utf-8") as sf:
            sf.write(str(f.tell()))
    return malicious_activity


def should_refresh_cf_ban(existing_row):
    if not existing_row:
        return False
    if existing_row.get("cf_banned") != 1:
        return True
    if existing_row.get("cf_ban_mode") != "temporary":
        return False
    expires_at = parse_iso(existing_row.get("cf_ban_expires_at"))
    return expires_at is not None and expires_at <= now_utc()


def process_ip(site, ip, data):
    domain = site["domain"]
    report_tag = f"[pon4ik-autoreporter] {domain} | "
    print(f"\n[*][{domain}] Processing violator: {ip} ({data['count']} requests, first attack: {data['first_seen']}, last: {data['last_seen']})")
    print(f"[*][{domain}] Triggered patterns: {', '.join(sorted(data['triggers']))}")
    existing_row = get_reported_ip_row(ip, domain)
    if existing_row and not should_refresh_cf_ban(existing_row):
        print(f"[~] {ip} already exists in the local DB for {domain}, skipping.")
        return
    local_skip, local_reason = should_skip_by_local_whitelist(ip)
    if local_skip:
        print(f"[~] {ip} whitelisted ({local_reason}), skipping.")
        return
    abuse_meta = abuseipdb_check_ip(ip, max_age_days=ABUSE_CHECK_MAX_AGE_DAYS, verbose=True, use_cache=True) or {}
    abuse_skip, abuse_reason = should_skip_by_abuse_metadata(abuse_meta)
    if abuse_skip:
        print(f"[~] {ip} whitelisted ({abuse_reason}), skipping.")
        return
    reported_already, reported_at = already_reported_by_me(abuse_meta, report_tag)
    if existing_row and should_refresh_cf_ban(existing_row):
        print(f"[~] {ip} already exists in the local DB for {domain}, refreshing CF ban.")
        cf_status, cf_rule_id, cf_ban_mode, cf_ban_expires_at = ban_in_cloudflare(ip, site["cf_zone_id"])
        save_ip_to_db(ip, domain, data["first_seen"], data["last_seen"], cf_banned=cf_status, abuse_meta=abuse_meta, last_comment="SKIPPED: local DB hit, CF ban refreshed", cf_rule_id=cf_rule_id, cf_ban_mode=cf_ban_mode, cf_ban_expires_at=cf_ban_expires_at)
        return
    if reported_already:
        print(f"[~] {ip} already reported by me previously ({reported_at}), no need to report again.")
        cf_status, cf_rule_id, cf_ban_mode, cf_ban_expires_at = ban_in_cloudflare(ip, site["cf_zone_id"])
        save_ip_to_db(ip, domain, data["first_seen"], data["last_seen"], cf_banned=cf_status, abuse_meta=abuse_meta, last_comment="SKIPPED: already reported by me", cf_rule_id=cf_rule_id, cf_ban_mode=cf_ban_mode, cf_ban_expires_at=cf_ban_expires_at)
        return
    abuse_success, comment, report_meta = report_to_abuseipdb(ip, domain, data, report_tag)
    cf_status, cf_rule_id, cf_ban_mode, cf_ban_expires_at = ban_in_cloudflare(ip, site["cf_zone_id"])
    if abuse_success:
        combined_meta = abuse_meta or {}
        if report_meta:
            combined_meta = {**combined_meta, **report_meta}
        save_ip_to_db(ip, domain, data["first_seen"], data["last_seen"], cf_banned=cf_status, abuse_meta=combined_meta, last_comment=comment, cf_rule_id=cf_rule_id, cf_ban_mode=cf_ban_mode, cf_ban_expires_at=cf_ban_expires_at)
    elif cf_status:
        save_ip_to_db(ip, domain, data["first_seen"], data["last_seen"], cf_banned=cf_status, abuse_meta=abuse_meta, last_comment="CF ban applied, AbuseIPDB report failed", cf_rule_id=cf_rule_id, cf_ban_mode=cf_ban_mode, cf_ban_expires_at=cf_ban_expires_at)


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
                print(f"[!] Error in worker: {e}")


def validate_sites_config():
    if not isinstance(SITES, list) or not SITES:
        print("[!] SITES_JSON .env is empty or invalid. Expected a JSON array of site configurations.")
        return False
    required = {"domain", "log_file", "state_file", "cf_zone_id"}
    for idx, site in enumerate(SITES, start=1):
        if not isinstance(site, dict):
            print(f"[!] Element SITES_JSON #{idx} is not an object")
            return False
        missing = sorted(required - set(site.keys()))
        if missing:
            print(f"[!] In SITES_JSON #{idx} missing fields: {', '.join(missing)}")
            return False
    return True


def main_loop():
    if not validate_sites_config():
        return
    init_db()
    print(f"[~] Starting in 24/7 mode, check interval: {CHECK_INTERVAL_SECONDS} sec. Sites: {len(SITES)}, workers: {PROCESS_WORKERS}, report_mode: serialized, cf_ban_mode: {CF_BAN_MODE}")
    while True:
        cleanup_expired_cloudflare_bans()
        for site in SITES:
            try:
                process_site(site)
            except Exception as e:
                print(f"[!] Unhandled error while processing {site['domain']}: {e}")
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n[~] Stopped by user.")