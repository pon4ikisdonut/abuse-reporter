# abuse-reporter

Автоматический демон для мониторинга access-логов nginx на нескольких сайтах, детекции подозрительных и вредоносных запросов, автоматической отправки репортов в AbuseIPDB и бана нарушителей через Cloudflare Firewall Access Rules.

Скрипт работает в режиме 24/7: раз в заданный интервал читает только новые строки логов, находит триггеры по регулярным выражениям, агрегирует активность по IP, проверяет, не отправлялся ли именно **ваш** репорт ранее, при необходимости отправляет новый репорт, банит адрес в Cloudflare и сохраняет историю в локальную SQLite базу [file:1][file:2].

## Возможности

- Мониторинг нескольких доменов/сайтов одновременно, каждый со своим лог-файлом, state-файлом и Cloudflare Zone ID [file:1].
- Инкрементальный парсинг логов: позиция в файле сохраняется, повторное чтение старых строк не выполняется [file:1].
- Большой набор паттернов детекции: секреты и конфиги, CMS-эндпоинты, path traversal, SQLi, XSS, RCE, log4j и прочее [file:1].
- Агрегация активности по IP за один цикл: количество запросов, уникальные URI, HTTP-методы, статусы, время первой и последней атаки [file:2].
- Проверка через AbuseIPDB `check` перед репортом [file:2].
- Пропуск повторного репорта только в том случае, если IP уже был зарепорчен этим же скриптом по вашему уникальному тегу в комментарии [file:1][file:2].
- Чужие репорты в AbuseIPDB не блокируют отправку вашего репорта [file:1].
- Автоматический бан IP через Cloudflare Firewall Access Rules [file:1].
- Локальная SQLite база для истории и отдельный кэш `ip_cache` для AbuseIPDB-ответов и reverse DNS [file:2].
- Whitelist по одиночным IP, подсетям CIDR, ASN и reverse DNS/hostname-шаблонам доверенных ботов [file:2].
- Базовая обработка rate limit AbuseIPDB через `429`, `Retry-After` и `X-RateLimit-*` заголовки [file:2].

## Требования и зависимости

### Python

Требуется Python 3.8+ [file:1].

Из внешних зависимостей нужен `requests`. Остальное используется из стандартной библиотеки Python: `sqlite3`, `ipaddress`, `socket`, `json`, `re`, `time`, `os`, `datetime` [file:1][file:2].

```bash
pip install requests
```

### Системные требования

Для работы с дефолтными путями нужны права на:

- чтение access-логов nginx;
- запись в SQLite-базу;
- запись в state-файлы [file:1].

Если запускаете не от root:

- дайте пользователю доступ на чтение логов, например через группу `adm` или `nginx`;
- поменяйте `DB_FILE` на путь внутри домашней директории или `/var/lib/abuse-reporter/`;
- убедитесь, что пользователь может писать `state_file` [file:1].

### Сторонние сервисы

- Аккаунт AbuseIPDB с API-ключом [file:2].
- Аккаунт Cloudflare с API token и Zone ID для каждого домена [file:1].

## Настройка

### 1. API-ключи

В этой версии ключи хранятся **прямо в коде**:

```python
ABUSE_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"
CF_API_TOKEN = "YOUR_CLOUDFLARE_API_TOKEN_HERE"
```

Замените значения в начале `abuse_reporter.py` на свои реальные токены [file:1].

### 2. Список сайтов

Каждый сайт задаётся отдельным словарём в `SITES` [file:1]:

```python
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
```

### 3. Основные параметры

```python
DB_FILE = "/var/db/abuse_reporter.db"
CHECK_INTERVAL_SECONDS = 60
ABUSE_CHECK_MAX_AGE_DAYS = 90
ABUSE_REPORT_CATEGORIES = "15,21"
REVERSE_DNS_CACHE_HOURS = 72
ABUSE_CHECK_CACHE_HOURS = 24
API_SLEEP_SECONDS_ON_429 = 300
```

Кратко:

- `ABUSE_CHECK_MAX_AGE_DAYS` — на сколько дней назад смотреть историю репортов в AbuseIPDB при поиске **вашего** репорта [file:2].
- `ABUSE_REPORT_CATEGORIES` — категории, которые отправляются в AbuseIPDB [file:2].
- `REVERSE_DNS_CACHE_HOURS` — TTL кэша reverse DNS [file:2].
- `ABUSE_CHECK_CACHE_HOURS` — TTL кэша ответов `check` [file:2].
- `API_SLEEP_SECONDS_ON_429` — пауза при достижении rate limit [file:2].

### 4. Whitelist

Whitelist разбит на несколько уровней [file:2].

#### Одиночные IP

```python
WHITE_LIST_IPS = {
    "127.0.0.1",
    "::1",
}
```

#### Подсети CIDR

```python
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
```

#### ASN

```python
WHITE_LIST_ASNS = {
    # "AS15169",
    # "AS32934",
    # "AS8075",
}
```

#### Reverse DNS / hostname

```python
WHITE_LIST_HOSTNAME_PATTERNS = [
    r"\.googlebot\.com$",
    r"\.google\.com$",
    r"\.search\.msn\.com$",
    r"\.bing\.com$",
    r"\.yandex\.ru$",
    r"\.yandex\.net$",
    r"\.crawl\.baidu\.com$",
]
```

Также скрипт автоматически игнорирует private/reserved/link-local/loopback адреса через `ipaddress` [file:2].

### 5. Паттерны детекции

`BAD_PATTERNS` — список регулярок для детекции подозрительных запросов: утечки секретов и конфигов, `.git`, `.svn`, `.ssh`, ключи, бэкапы, WordPress, phpMyAdmin, adminer, traversal, SQLi, XSS, RCE и log4j-подобные сигнатуры [file:1].

## Формат логов nginx

По умолчанию `LOG_PATTERN` рассчитан на классический access log, близкий к `combined` [file:1]:

```text
<IP> - - [<дата>] "<METHOD> <URL> HTTP/1.1" <status> ...
```

Если у вас кастомный `log_format`, нужно адаптировать `LOG_PATTERN`, иначе строки не будут матчиться [file:1].

## Как работает скрипт

1. Создаёт SQLite таблицы `reported_ips` и `ip_cache`, если их ещё нет [file:2].
2. Для каждого сайта читает лог только с последней сохранённой позиции [file:1].
3. Парсит IP, URL, метод, статус и timestamp [file:1].
4. Прогоняет IP через whitelist: одиночный IP, CIDR, private/reserved, reverse DNS, ASN и `usageType` из AbuseIPDB [file:2].
5. Если URL совпал с паттернами, агрегирует активность по IP [file:1].
6. Проверяет локальную БД `reported_ips` [file:1].
7. Выполняет AbuseIPDB `check` [file:2].
8. Проверяет массив `reports` и ищет в комментариях ваш уникальный `report_tag`; если найден именно ваш репорт, повторно IP не репортится [file:1][file:2].
9. Если найден только чужой репорт, это не мешает отправить ваш собственный [file:1].
10. Если IP считается новым именно для вашего скрипта, выполняется POST в AbuseIPDB `report` с `ip`, `categories`, `comment`, `timestamp` [file:2].
11. После этого IP блокируется через Cloudflare [file:1].
12. Результат сохраняется в локальную базу [file:2].

Схема:

```text
логи -> парсинг -> whitelist -> детекция -> агрегация по IP
     -> локальная БД -> AbuseIPDB check -> поиск моего report_tag
     -> skip только если репорт уже мой
     -> иначе report -> Cloudflare ban -> запись в SQLite
```

## Куда вставлять логику проверки

Если у вас старая версия `process_site(site)`, новый блок нужно вставлять **внутри цикла `for ip, data in bad_ips.items():`**, сразу после проверки локальной БД `is_ip_in_local_db(ip, domain)` и **вместо** старого блока с `reported_already` и `report_to_abuseipdb` [file:1].

Было:

```python
        reported_already, reported_at = already_reported_by_me(ip, report_tag)

        if reported_already:
            cf_status = ban_in_cloudflare(ip, site["cf_zone_id"])
            save_ip_to_db(ip, domain, data["first_seen"], data["last_seen"], cf_banned=cf_status)
            continue

        abuse_success = report_to_abuseipdb(ip, data, report_tag)
        cf_status = ban_in_cloudflare(ip, site["cf_zone_id"])
```

Стало:

```python
        abuse_meta = abuseipdb_check_ip(ip, max_age_days=ABUSE_CHECK_MAX_AGE_DAYS, verbose=False, use_cache=True) or {}

        reported_already, reported_at = already_reported_by_me(ip, report_tag)
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
            continue

        abuse_success, comment, report_meta = report_to_abuseipdb(ip, domain, data, report_tag)
        cf_status = ban_in_cloudflare(ip, site["cf_zone_id"])
```

## AbuseIPDB API

Скрипт использует два endpoint’а [file:2][page:1]:

### `GET /api/v2/check`

Используется для проверки IP перед репортом и для поиска ваших старых репортов по `report_tag` [file:2][page:1].

Параметры:

- `ipAddress`
- `maxAgeInDays`
- `verbose` — нужен, когда требуется массив `reports` [file:2][page:1].

### `POST /api/v2/report`

Используется для отправки репорта [file:2][page:1].

Параметры:

- `ip`
- `categories`
- `comment`
- `timestamp` [file:2][page:1].

Скрипт передаёт в `timestamp` значение `first_seen`, чтобы фиксировать реальное время наблюдения атаки [file:2][page:1].

### Rate limit

При превышении лимита AbuseIPDB возвращает `429 Too Many Requests`, а полезные данные доступны в заголовках:

- `Retry-After`
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset` [file:2][page:1].

## Cloudflare

Для бана используется endpoint IP Access Rules [file:1]:

```text
POST /client/v4/zones/{zone_id}/firewall/access_rules/rules
```

Если `CF_API_TOKEN` или `cf_zone_id` не заданы, бан просто пропускается без падения процесса [file:2].

## Запуск

```bash
python3 abuse_reporter.py
```

## systemd

Для 24/7-режима лучше запускать как systemd unit [file:1].

### Пример unit-файла

`/etc/systemd/system/abuse-reporter.service`

```ini
[Unit]
Description=Abuse Reporter Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/abuse-reporter
ExecStart=/usr/bin/python3 /opt/abuse-reporter/abuse_reporter.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Команды управления

```bash
systemctl daemon-reload
systemctl enable --now abuse-reporter
systemctl status abuse-reporter
journalctl -u abuse-reporter -f
```

## Ограничения и особенности

- При первом запуске без `state_file` скрипт обработает лог с начала текущего файла [file:1].
- При агрессивной ротации логов между циклами возможна потеря части строк [file:1].
- Reverse DNS lookup и AbuseIPDB-проверки хоть и кэшируются, но всё равно добавляют сетевую задержку [file:2].
- Whitelist по reverse DNS не является строгой криптографической верификацией бота [file:2].
- В `comment` нельзя сливать PII или чувствительные данные; AbuseIPDB прямо предупреждает об этом в документации [file:2][page:1].

## Безопасность

- Не публикуйте файл с реальными токенами в публичный репозиторий, если оставляете хардкод [file:1].
- Ограничьте права на SQLite базу и state-файлы [file:1].
- Выдавайте Cloudflare token с минимально необходимыми правами на конкретные зоны [file:1].
- Не добавляйте в `comment` токены, cookie, session id, Authorization headers и прочие чувствительные данные [file:2][page:1].

## Лицензия

Проект распространяется на условиях лицензии MIT. Подробности — в файле `LICENSE`.