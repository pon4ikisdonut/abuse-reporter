# abuse-reporter

Автоматический демон для мониторинга access-логов nginx на нескольких сайтах, детекции подозрительных и вредоносных запросов, автоматической отправки репортов в AbuseIPDB и бана нарушителей через Cloudflare Access Rules.

Скрипт работает в режиме 24/7: раз в заданный интервал читает только новые строки логов, находит триггеры по регулярным выражениям, агрегирует активность по IP, проверяет, не отправлялся ли именно **ваш** репорт ранее, при необходимости отправляет новый репорт, банит адрес в Cloudflare и сохраняет историю в локальную SQLite-базу.

---

## Возможности

- Мониторинг нескольких доменов/сайтов одновременно, каждый со своим `log_file`, `state_file` и `cf_zone_id`.
- Инкрементальный парсинг логов: позиция в файле сохраняется в `state_file`, старые строки повторно не читаются.
- Большой набор паттернов детекции: секреты и конфиги, `.git`, `.svn`, `.ssh`, CMS-эндпоинты, path traversal, SQLi, XSS, RCE, log4j и прочее.
- Агрегация активности по IP за один цикл: количество запросов, уникальные URI, HTTP-методы, статусы, время первой и последней атаки.
- Нормализация IPv4/IPv6 через `ipaddress`.
- Проверка IP через AbuseIPDB `check` перед репортом.
- Пропуск повторного репорта только в том случае, если IP уже был зарепорчен этим же скриптом по вашему уникальному тегу в комментарии.
- Чужие репорты в AbuseIPDB не блокируют отправку вашего репорта.
- Автоматический бан IP через Cloudflare Access Rules.
- Локальная SQLite-база для истории `reported_ips` и отдельный кэш `ip_cache` для reverse DNS и AbuseIPDB-ответов.
- Whitelist по одиночным IP, подсетям CIDR, ASN и reverse DNS/hostname-шаблонам.
- Кэширование reverse DNS и AbuseIPDB `check`.
- Базовая защита от rate limit AbuseIPDB: интервалы между запросами, сериализация `report`, обработка `429`, `Retry-After` и `X-RateLimit-*`.

---

## Требования и зависимости

### Python

Требуется Python 3.8+.

Внешняя зависимость только одна:

```bash
pip install requests
```

Используются стандартные модули Python:

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

### Системные требования

Для работы с дефолтными путями нужны права на:

- чтение access-логов nginx;
- запись в SQLite-базу;
- запись в `state_file`.

Если запускаете не от root:

- дайте пользователю доступ на чтение логов, например через группу `adm` или `nginx`;
- измените `DB_FILE` на путь вроде `/var/lib/abuse-reporter/abuse_reporter.db` или в домашнюю директорию;
- убедитесь, что пользователь может создавать и обновлять `state_file`.

### Сторонние сервисы

- Аккаунт AbuseIPDB с API-ключом.
- Аккаунт Cloudflare с API token и Zone ID для каждого домена.
- Для AbuseIPDB рекомендуется передавать API key через HTTP-заголовок `Key`, а не в query string. [page:2]

---

## Настройка

### 1. API-ключи

В текущей версии ключи заданы прямо в коде:

```python
ABUSE_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"
CF_API_TOKEN = "YOUR_CLOUDFLARE_API_TOKEN_HERE"
```

Замените их на реальные значения.

> Важно: не коммитьте реальные токены в публичный репозиторий.

### 2. Список сайтов

Каждый сайт задаётся отдельным словарём в `SITES`:

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

Поля:

- `domain` — домен, который будет фигурировать в комментарии репорта;
- `log_file` — путь к access-логу nginx;
- `state_file` — файл с последней прочитанной позицией;
- `cf_zone_id` — Cloudflare Zone ID для блокировки IP в соответствующей зоне.

### 3. Основные параметры

```python
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
```

Кратко:

- `DB_FILE` — путь к SQLite-базе.
- `CHECK_INTERVAL_SECONDS` — интервал между циклами обработки.
- `ABUSE_CHECK_MAX_AGE_DAYS` — глубина истории репортов при `check`.
- `ABUSE_REPORT_CATEGORIES` — категории, которые отправляются в AbuseIPDB.
- `ABUSE_REQUEST_TIMEOUT` — timeout HTTP-запросов к AbuseIPDB.
- `ABUSE_COMMENT_MAX_LEN` — максимальная длина комментария репорта.
- `REVERSE_DNS_CACHE_HOURS` — TTL кэша reverse DNS.
- `ABUSE_CHECK_CACHE_HOURS` — TTL кэша результата `check`.
- `ABUSE_MIN_REQUEST_INTERVAL_SECONDS` — базовый минимальный интервал между запросами к AbuseIPDB.
- `ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS` — отдельный интервал для `check`.
- `ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS` — отдельный интервал для `report`.
- `PROCESS_WORKERS` — число worker-потоков на обработку IP внутри одного сайта.
- `SQLITE_TIMEOUT` — timeout ожидания блокировки SQLite.

> В старом README параметр `API_SLEEP_SECONDS_ON_429` был указан, но в текущем коде его **нет**. Вместо этого используется динамический backoff через `Retry-After`.

### 4. Whitelist

Whitelist разбит на несколько уровней.

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

Дополнительно скрипт автоматически пропускает private/reserved/link-local/loopback/multicast/unspecified адреса через `ipaddress`.

### 5. Паттерны детекции

`BAD_PATTERNS` — это список регулярных выражений для поиска подозрительных запросов, например:

- `.env`, `.git`, `.svn`, `.ssh`, ключи, бэкапы, дампы БД;
- `wp-login.php`, `xmlrpc.php`, `phpmyadmin`, `adminer.php`, `vendor/phpunit`;
- path traversal (`../`, `%2e%2e`);
- SQLi (`union select`, `information_schema`, `sleep()`);
- XSS (`<script`);
- RCE / downloader-сигнатуры (`exec(`, `wget`, `curl http`);
- log4j (`${jndi:`).

---

## Формат логов nginx

По умолчанию `LOG_PATTERN` рассчитан на обычный access log формата, близкого к `combined`:

```text
<IP> - - [<date>] "<METHOD> <URL> HTTP/1.1" <status> ...
```

Фактически из строки извлекаются:

- IP
- дата
- HTTP-метод
- URL
- статус ответа

Если у вас кастомный `log_format`, нужно адаптировать `LOG_PATTERN`, иначе строки не будут матчиться.

---

## Как работает скрипт

1. Создаёт SQLite-таблицы `reported_ips` и `ip_cache`, если их ещё нет.
2. Для каждого сайта читает лог только с последней сохранённой позиции.
3. Парсит IP, URL, метод, статус и timestamp.
4. Ищет совпадения URL с `BAD_PATTERNS`.
5. Агрегирует вредоносную активность по IP в рамках текущего цикла.
6. Проверяет, есть ли IP уже в локальной таблице `reported_ips` для данного домена.
7. Прогоняет IP через локальный whitelist: одиночные IP, CIDR, private/reserved и reverse DNS.
8. Делает AbuseIPDB `check` с `verbose=True`, чтобы получить список прошлых `reports`, если IP ещё не отсеян.
9. Применяет дополнительный whitelist по данным AbuseIPDB: `isPublic`, ASN и `usageType`.
10. Ищет в прошлых `reports` свой уникальный `report_tag` в комментариях.
11. Если **именно ваш** репорт уже есть, повторный репорт не отправляется, но Cloudflare ban всё равно может быть выполнен.
12. Если вашего репорта нет, отправляется новый `report` в AbuseIPDB.
13. После этого IP блокируется через Cloudflare.
14. Итог записывается в SQLite.

Схема:

```text
логи -> парсинг -> regex trigger -> агрегация по IP
     -> локальная БД -> local whitelist -> AbuseIPDB check
     -> whitelist по abuse metadata -> поиск моего report_tag
     -> skip только если репорт уже мой
     -> иначе report -> Cloudflare ban -> запись в SQLite
```

---

## Структура SQLite

### Таблица `reported_ips`

Хранит факт обработки IP по конкретному домену:

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

Первичный ключ:

```sql
PRIMARY KEY (ip, domain)
```

Это значит, что один и тот же IP может храниться отдельно для разных доменов.

### Таблица `ip_cache`

Хранит кэш об IP:

- reverse DNS;
- время проверки reverse DNS;
- JSON из AbuseIPDB `check`;
- время проверки AbuseIPDB;
- ASN;
- `usageType`;
- `abuseConfidenceScore`;
- `totalReports`;
- `lastReportedAt`;
- `countryCode`;
- флаги `is_whitelisted`, `is_public`, `is_tor`.

---

## AbuseIPDB API

Скрипт использует endpoint’ы `check` и `report` API v2. [page:2][web:1]

### `GET /api/v2/check`

Используется для проверки IP перед репортом и для поиска ваших прошлых репортов по `report_tag`. [page:2]

Параметры:

- `ipAddress`
- `maxAgeInDays`
- `verbose`

`verbose` нужен, если вы хотите получить массив `reports`; без него отчёты не возвращаются. [page:2]

`maxAgeInDays` может быть от 1 до 365, а значение по умолчанию у AbuseIPDB — 30 дней. [page:2]

Скрипт делает запрос примерно в таком виде:

```python
params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}
```

### `POST /api/v2/report`

Используется для отправки нового репорта. [page:2]

Параметры:

- `ip`
- `categories`
- `comment`
- `timestamp` [page:2]

`comment` у AbuseIPDB ограничен 1024 символами, поэтому в коде есть `truncate_comment()`. [page:2]

`timestamp` принимает ISO 8601 datetime и может отражать реальное время наблюдения атаки, а не только текущее время отправки. [page:2]

Скрипт передаёт в `timestamp` значение `first_seen`.

### Почему используется свой `report_tag`

AbuseIPDB возвращает массив прошлых отчётов для IP при `verbose`, и скрипт проверяет именно наличие **вашего** уникального тега в `comment`, а не просто факт существования любого старого репорта. [page:2]

Это важно, потому что чужие репорты не должны мешать отправить ваш собственный репорт.

### Rate limit

При превышении лимита AbuseIPDB отвечает `429 Too Many Requests` и возвращает полезные заголовки `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining` и `X-RateLimit-Reset`. [page:2]

В коде это используется так:

- для `check`, `report` и прочих запросов заданы отдельные минимальные интервалы;
- при `429` берётся `Retry-After`;
- затем обновляется общий backoff через `set_abuse_backoff()`.

Также AbuseIPDB отдельно указывает, что тестовый IP `127.0.0.2` можно использовать для симуляции краткосрочного rate limit на `report`. [page:2]

---

## Cloudflare

Для бана используется Cloudflare Access Rules API по пути `POST /{accounts_or_zones}/{account_or_zone_id}/firewall/access_rules/rules`. [page:1]

Для одиночного IPv4-адреса `configuration.target` должен быть `ip`, а для IPv6 — `ip6`, что и делает текущий код. [page:1]

В текущей реализации отправляется тело:

```json
{
  "mode": "block",
  "configuration": {
    "target": "ip",
    "value": "1.2.3.4"
  },
  "notes": "Automated ban by abuse_reporter.py for malicious web probing"
}
```

Cloudflare Access Rules поддерживает режимы вроде `block`, `challenge`, `whitelist`, `js_challenge` и `managed_challenge`, но ваш код использует именно `block`. [page:1]

Если `cf_zone_id` не задан или `CF_API_TOKEN` не настроен, Cloudflare ban пропускается без падения процесса.

---

## Параллелизм и rate limiting

В коде используется `ThreadPoolExecutor`, но есть несколько важных деталей:

- `PROCESS_WORKERS` ограничивает число параллельных worker’ов на один сайт.
- HTTP-сессия `requests.Session()` хранится в `thread_local`.
- Запросы к AbuseIPDB проходят через единый rate limit-контур.
- Отправка `report` дополнительно сериализована через `report_submit_lock`.

То есть `check` может выполняться конкурентно, но `report` фактически защищён от гонок сильнее, чем в старых версиях.

---

## Запуск

```bash
python3 abuse_reporter.py
```

При старте скрипт пишет что-то вроде:

```text
[~] Запуск в режиме 24/7, интервал проверки: 60 сек. Сайтов: N, workers: 2, report_mode: serialized
```

Остановить можно через `Ctrl+C`.

---

## systemd

Для 24/7-режима удобнее запускать как systemd unit.

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

---

## Ограничения и особенности

- При первом запуске без `state_file` скрипт обработает лог с начала текущего файла.
- Если `state_file` повреждён и не парсится как число, позиция будет сброшена в `0`.
- Если лог ротировался и прежняя позиция стала больше нового размера файла, чтение начнётся с начала нового файла.
- При агрессивной ротации между циклами часть строк всё равно можно потерять.
- Reverse DNS и AbuseIPDB `check` кэшируются, но всё равно добавляют сетевую задержку.
- Whitelist по reverse DNS не является строгой верификацией поискового бота.
- В коде нет отдельной дедупликации по `comment` вне механизма `report_tag`.
- В `reported_ips` запись создаётся только если IP уже был репорчен вами ранее или если новый репорт успешно ушёл в AbuseIPDB; при неуспешном `report` IP не фиксируется как обработанный.
- Cloudflare ban выполняется даже в ветке `already reported by me`.

---

## Безопасность

- Не храните реальные токены в публичном репозитории.
- Ограничьте права на SQLite-базу и `state_file`.
- Желательно перенести секреты в переменные окружения или systemd `EnvironmentFile`.
- Выдавайте Cloudflare token с минимально необходимыми правами только на нужные зоны.
- Не включайте в `comment` токены, cookie, session id, Authorization headers и прочие чувствительные данные.
- AbuseIPDB рекомендует использовать HTTPS и передавать API key в заголовке, потому что query string может попасть в логи промежуточных систем. [page:2]

---

## Что было исправлено относительно старого README

- Убран несуществующий параметр `API_SLEEP_SECONDS_ON_429`.
- Добавлены реальные параметры: `ABUSE_REQUEST_TIMEOUT`, `ABUSE_COMMENT_MAX_LEN`, `ABUSE_MIN_REQUEST_INTERVAL_SECONDS`, `ABUSE_CHECK_MIN_REQUEST_INTERVAL_SECONDS`, `ABUSE_REPORT_MIN_REQUEST_INTERVAL_SECONDS`, `PROCESS_WORKERS`, `SQLITE_TIMEOUT`.
- Исправлено описание `already_reported_by_me()`: функция принимает `abuse_data`, а не IP.
- Исправлено описание новой архитектуры: логика вынесена в `process_ip()`, а не в старый inline-цикл внутри `process_site()`.
- Добавлено описание `ip_cache`, reverse DNS cache и AbuseIPDB cache.
- Исправлено описание rate limiting: теперь это не sleep-константа, а per-endpoint интервалы + backoff.
- Уточнён Cloudflare endpoint и типы `configuration.target` для IPv4/IPv6. [page:1]
- Уточнено, что для получения массива прошлых репортов у AbuseIPDB нужен `verbose`. [page:2]

---

## Лицензия

Проект распространяется на условиях лицензии MIT. Подробности — в файле `LICENSE`.