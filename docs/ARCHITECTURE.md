# Архитектура NetMCP

## Обзор системы

NetMCP — профессиональный MCP-сервер для сетевого анализа. Построен на FastMCP (официальный Python SDK для Model Context Protocol). Предоставляет AI-ассистентам возможности захвата пакетов, сканирования сети, анализа угроз и извлечения учётных данных.

## Компонентная диаграмма

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Client                               │
│              (Claude Desktop / Cursor / VS Code)                │
└──────────────────────────┬──────────────────────────────────────┘
                           │ MCP Protocol (stdio / SSE / HTTP)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FastMCP Server                             │
│                      (server.py)                                │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐                     │
│  │ Resources │  │ Prompts  │  │   Tools   │                     │
│  │    (3)    │  │   (5)    │  │   (25)    │                     │
│  └──────────┘  └──────────┘  └─────┬─────┘                     │
└────────────────────────────────────┼────────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│       Core       │  │    Interfaces    │  │   Tools Layer    │
│  ┌─────────────┐ │  │  ┌────────────┐  │  │  ┌────────────┐  │
│  │  Security   │ │  │  │  TShark    │  │  │  │  capture   │  │
│  │  Validator  │ │  │  │ Interface  │  │  │  │  analysis  │  │
│  ├─────────────┤ │  │  ├────────────┤  │  │  │  streams   │  │
│  │   Output    │ │  │  │   Nmap     │  │  │  │  export    │  │
│  │  Formatter  │ │  │  │ Interface  │  │  │  │  nmap_scan │  │
│  └─────────────┘ │  │  ├────────────┤  │  │  │  threat    │  │
│                  │  │  │ ThreatIntel│  │  │  │  creds     │  │
│                  │  │  │ Interface  │  │  │  └────────────┘  │
└──────────────────┘  │  └────────────┘  │  └──────────────────┘
                      └────────┬─────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
        ┌──────────┐   ┌──────────┐    ┌──────────────┐
        │  tshark  │   │   nmap   │    │  URLhaus /   │
        │ (binary) │   │ (binary) │    │  AbuseIPDB   │
        └──────────┘   └──────────┘    └──────────────┘
```

## Поток данных

```
User ──► MCP Client ──► FastMCP Server ──► Tool Function
                                               │
                                    ┌──────────┤
                                    ▼          ▼
                              SecurityValidator  Interface
                              (validate input)   (execute)
                                    │              │
                                    ▼              ▼
                              Rate Limiter    Subprocess
                              Audit Logger   (shell=False)
                                                   │
                                                   ▼
                                            OutputFormatter
                                            (format response)
                                                   │
                                                   ▼
                                            MCP Response ──► Client
```

## Архитектурные решения (ADR)

### ADR-001: Модульная структура пакета

**Контекст**: Выбор между монолитным файлом (как WireMCP — один server.js) и модульной структурой.

**Решение**: Трёхуровневая модульная архитектура: `core` → `interfaces` → `tools`.

**Обоснование**:
- Разделение ответственности (Single Responsibility Principle)
- Каждый интерфейс можно тестировать изолированно
- Новый инструмент добавляется без изменения существующего кода (Open/Closed Principle)
- Инструменты зависят от интерфейсов, а не от конкретных реализаций

**Последствия**:
- Больше файлов, но каждый файл понятен и самодостаточен
- Простое добавление новых категорий инструментов
- Параллельная разработка разных модулей

**Альтернативы**:
- Монолит (WireMCP): прост в начале, но не масштабируется
- Flat structure: быстро становится хаотичным

### ADR-002: shell=False во всех subprocess-вызовах

**Контекст**: TShark и Nmap запускаются как внешние процессы. Использование `shell=True` — распространённая ошибка (WireMCP использует `shell=true` в Node.js).

**Решение**: Абсолютный запрет `shell=True`. Все команды строятся как списки аргументов.

**Обоснование**:
- `shell=True` + пользовательский ввод = command injection
- WireMCP демонстрирует эту уязвимость: передача пользовательского ввода в shell-команду без валидации
- Даже при наличии валидации, `shell=False` — это defense in depth

**Реализация**:
```python
# ❌ Опасно
subprocess.run(f"tshark -r {filepath}", shell=True)

# ✅ Безопасно
subprocess.run(["tshark", "-r", str(filepath)], shell=False)
```

**Последствия**:
- Невозможность command injection через пользовательский ввод
- Необходимость ручного построения списков аргументов
- Невозможность использования shell features (пайпы, редиректы)

### ADR-003: Rate Limiting + Audit Logging

**Контекст**: MCP-сервер доступен AI-ассистенту, который может многократно вызывать инструменты. Без ограничений возможны DoS-атаки или злоупотребление.

**Решение**: Скользящее окно rate limiting + аудит-логирование всех операций.

**Обоснование**:
- Захват пакетов нагружает сетевой интерфейс (лимит: 30/час)
- Сканирование Nmap нагружает цель (лимит: 10/час)
- Запросы к API имеют свои лимиты (threat_intel: 100/час)
- Извлечение учётных данных — чувствительная операция, требующая логирования

**Реализация**: Thread-safe скользящее окно с `threading.Lock()`. Операции логируются с метками времени. Чувствительные поля (password, token, key) автоматически маскируются.

**Лимиты**:
| Операция | Лимит | Обоснование |
|----------|-------|-------------|
| `live_capture` | 30/час | Нагрузка на сетевой интерфейс |
| `nmap_scan` | 10/час | Нагрузка на целевой хост |
| `threat_intel` | 100/час | Лимиты внешних API |
| `threat_scan` | 10/час | Массовые запросы к API |

### ADR-004: Dependency Injection для SecurityValidator и OutputFormatter

**Контекст**: Инструменты нуждаются в валидации входных данных и форматировании выходных. Как передавать эти зависимости?

**Решение**: Dependency Injection через `register_*_tools(mcp, interface, formatter, security)`.

**Обоснование**:
- Инструменты не создают свои экземпляры зависимостей
- Один SecurityValidator на весь сервер (единый rate limiter)
- Один OutputFormatter гарантирует единообразие ответов
- Простое подключение mock-объектов в тестах

**Реализация**:
```python
# server.py — создание зависимостей
sec = SecurityValidator()
fmt = OutputFormatter()
tshark = TsharkInterface(tshark_path)

# Инъекция в каждую группу инструментов
register_capture_tools(mcp, tshark, fmt, sec)
register_analysis_tools(mcp, tshark, fmt, sec)
register_nmap_tools(mcp, nmap, fmt, sec)
```

**Последствия**:
- Единый rate limiter для всех инструментов
- Тестирование с mock-зависимостями тривиально
- Явные зависимости каждого модуля

### ADR-005: Асинхронные инструменты с синхронным subprocess

**Контекст**: MCP SDK (FastMCP) использует asyncio. TShark и Nmap — синхронные CLI-утилиты.

**Решение**: Инструменты определены как `async def`, subprocess-вызовы выполняются через `asyncio.create_subprocess_exec()`.

**Обоснование**:
- FastMCP требует async tool functions
- `asyncio.create_subprocess_exec()` не блокирует event loop
- Таймауты через `asyncio.wait_for()` гарантируют завершение
- Возможность параллельного выполнения нескольких инструментов

### ADR-006: Валидация входных данных на уровне SecurityValidator

**Контекст**: Пользовательский ввод проходит через AI-ассистента, но остаётся ненадёжным.

**Решение**: Централизованная валидация в SecurityValidator с отдельными методами для каждого типа данных.

**Методы валидации**:
- `validate_interface()` — имя сетевого интерфейса
- `validate_target()` — IP/CIDR/hostname
- `validate_port_range()` — спецификация портов
- `validate_capture_filter()` — BPF фильтры
- `validate_display_filter()` — Wireshark display filters
- `sanitize_filepath()` — путь к файлу (no traversal, no symlinks, extension check, size limit)
- `validate_nmap_arguments()` — аргументы nmap (allowlist + blocklist)

**Паттерны защиты**:
- Shell metacharacters `[;|&$\`{}!]` запрещены во всех строковых входах
- IP-адреса проверяются через `ipaddress` модуль Python
- Пути файлов резолвятся и проверяются на traversal
- Nmap аргументы проверяются по whitelist разрешённых флагов

## Слои системы

### Core Layer
Независимый от MCP. Может использоваться в любом Python-приложении.
- `SecurityValidator` — валидация, rate limiting, audit logging
- `OutputFormatter` — JSON/text форматирование, error codes, таблицы

### Interfaces Layer
Обёртки над внешними инструментами. Скрывают детали запуска процессов.
- `TsharkInterface` — async обёртка для tshark CLI
- `NmapInterface` — обёртка для python-nmap
- `ThreatIntelInterface` — клиент URLhaus + AbuseIPDB с кешированием

### Tools Layer
MCP tool functions. Связывают интерфейсы с MCP через декораторы FastMCP.
- 7 модулей: capture, analysis, streams, export, nmap_scan, threat_intel, credentials

### Resources Layer
MCP resources — данные, доступные клиенту для чтения.
- interfaces, captures, system/info

### Prompts Layer
MCP prompts — шаблоны рабочих процессов для AI-ассистента.
- security_audit, network_troubleshooting, incident_response, traffic_analysis, network_baseline

## Модель обработки ошибок

Структурированные коды ошибок:

| Код | Название | Описание |
|-----|----------|----------|
| `NETMCP_001` | Internal | Непредвиденная внутренняя ошибка |
| `NETMCP_002` | Validation | Ошибка валидации входных данных |
| `NETMCP_003` | Tool Execution | Ошибка внешнего инструмента |
| `NETMCP_004` | File Error | Файл не найден / нет доступа |
| `NETMCP_005` | Timeout | Превышение таймаута |
| `NETMCP_006` | Rate Limited | Превышение лимита запросов |
| `NETMCP_007` | Permission | Недостаточно прав |
| `NETMCP_008` | Not Available | Инструмент не установлен |

Автоматическое отображение Python-исключений на коды ошибок:
- `ValueError` → NETMCP_002
- `FileNotFoundError` → NETMCP_004
- `TimeoutError` → NETMCP_005
- `PermissionError` → NETMCP_007

## Кеширование

ThreatIntelInterface использует in-memory кеш:
- TTL: 3600 секунд (1 час)
- Максимальный размер: 10,000 записей
- LRU-вытеснение: при превышении удаляется 25% старейших записей
- Ключ: `f"{provider}:{ip}"`
