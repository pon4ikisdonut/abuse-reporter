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
    config["DNS_TIMEOUT_SECONDS"] = env_float("DNS_TIMEOUT_SECONDS", 3.0)
    config["ABUSE_CHECK_CACHE_HOURS"] = env_int("ABUSE_CHECK_CACHE_HOURS", 24)
    config["ABUSE_MIN_REQUEST_INTERVAL_SECONDS"] = env_float("ABUSE_MIN_REQUEST_INTERVAL_SECONDS", 2.0)
    config["ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS"] = env_float("ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS", 2.0)
    config["ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS"] = env_float("ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS", 15.0)
    config["PROCESS_WORKERS"] = env_int("PROCESS_WORKERS", 8)
    config["SQLITE_TIMEOUT"] = env_int("SQLITE_TIMEOUT", 30)
    config["CF_BAN_MODE"] = env_str("CF_BAN_MODE", "permanent").lower()
    config["CF_TEMP_BAN_MINUTES"] = env_int("CF_TEMP_BAN_MINUTES", 60)
    config["CF_REQUEST_TIMEOUT"] = env_int("CF_REQUEST_TIMEOUT", 15)
    config["WHITE_LIST_IPS"] = set(env_list("WHITE_LIST_IPS", ["127.0.0.1", "::1"]))
    config["WHITE_LIST_CIDRS"] = env_list("WHITE_LIST_CIDRS", [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
    ])
    config["WHITE_LIST_ASNS"] = set(item.upper() for item in env_list("WHITE_LIST_ASNS", []))
    config["WHITE_LIST_HOSTNAME_PATTERNS"] = env_list("WHITE_LIST_HOSTNAME_PATTERNS", [
        r"\.googlebot\.com$", r"\.google\.com$", r"\.search\.msn\.com$",
        r"\.bing\.com$", r"\.yandex\.ru$", r"\.yandex\.net$", r"\.crawl\.baidu\.com$",
    ])
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
DNS_TIMEOUT_SECONDS = CONFIG["DNS_TIMEOUT_SECONDS"]
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

# Never allow reverse DNS to block a worker indefinitely.
socket.setdefaulttimeout(max(0.5, DNS_TIMEOUT_SECONDS))

# ... existing pattern rules and the rest of the module remain unchanged ...
