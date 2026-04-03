"""MCP Prompts for NetMCP — guided workflows."""

from mcp.server.fastmcp import FastMCP


def register_prompts(mcp: FastMCP) -> None:
    """Register MCP prompts."""

    @mcp.prompt()
    def security_audit() -> str:
        """Comprehensive network security audit workflow."""
        return """# Аудит сетевой безопасности

## Шаг 1: Обзор трафика
Используйте `analyze_pcap` для общего обзора захваченного трафика.

## Шаг 2: Проверка учётных данных
Используйте `extract_credentials` для поиска утечек паролей в открытом виде.

## Шаг 3: Анализ TLS
Используйте `analyze_tls_handshake` для проверки версий TLS и шифров.
Проверьте использование устаревших TLS 1.0/1.1.

## Шаг 4: DNS-анализ
Используйте `analyze_dns_traffic` для выявления DNS-туннелирования и подозрительных запросов.

## Шаг 5: Проверка угроз
Используйте `check_threat_intelligence` для проверки IP-адресов по базам угроз.

## Шаг 6: Экспертная информация
Используйте `get_expert_info` для просмотра предупреждений Wireshark.

## Шаг 7: Отчёт
Используйте `generate_report` для создания полного отчёта."""

    @mcp.prompt()
    def network_troubleshooting() -> str:
        """Network troubleshooting workflow."""
        return """# Диагностика сетевых проблем

## Шаг 1: Захват трафика
Используйте `quick_capture` или `capture_targeted_traffic` для захвата.

## Шаг 2: Обзор протоколов
Используйте `get_protocol_hierarchy` для общей картины.

## Шаг 3: Потоки TCP
Используйте `visualize_network_flows` для визуализации потоков.
Проверьте `get_expert_info` на ретрансмиссии и ошибки.

## Шаг 4: Анализ DNS
Используйте `analyze_dns_traffic` для проверки DNS-разрешения.

## Шаг 5: HTTP-проблемы
Используйте `analyze_http_traffic` для поиска ошибок (4xx/5xx).

## Шаг 6: Диалоги
Используйте `get_conversation_stats` для определения нагрузки."""

    @mcp.prompt()
    def incident_response() -> str:
        """Incident response investigation workflow."""
        return """# Расследование инцидента

## Фаза 1: Идентификация
Используйте `get_capture_info` для метаданных файла.
Используйте `analyze_pcap` для первичного обзора.

## Фаза 2: Анализ IoC
Используйте `check_threat_intelligence` для проверки IP-адресов.
Используйте `extract_credentials` для поиска скомпрометированных учётных данных.

## Фаза 3: Анализ трафика
Используйте `deep_packet_analysis` для детального разбора.
Используйте `follow_tcp_stream` для реконструкции сессий.

## Фаза 4: Извлечение артефактов
Используйте `extract_objects` для извлечения файлов из трафика.
Используйте `export_packets_json` для экспорта улик.

## Фаза 5: Хронология
Используйте `get_io_statistics` для временной шкалы активности.
Используйте `get_flow_statistics` для анализа потоков.

## Фаза 6: Документирование
Используйте `generate_report` для создания отчёта об инциденте."""

    @mcp.prompt()
    def traffic_analysis() -> str:
        """General traffic analysis workflow."""
        return """# Анализ сетевого трафика

## Шаг 1: Обзор
Используйте `analyze_pcap` и `get_protocol_hierarchy`.

## Шаг 2: Статистика
Используйте `get_io_statistics` для временных графиков.
Используйте `get_conversation_stats` для топ-соединений.

## Шаг 3: Протоколы
Используйте `analyze_http_traffic` для HTTP.
Используйте `analyze_dns_traffic` для DNS.

## Шаг 4: Потоки
Используйте `visualize_network_flows` для визуализации.
Используйте `follow_tcp_stream` для содержимого потоков.

## Шаг 5: Безопасность
Используйте `get_expert_info` для предупреждений.
Используйте `check_threat_intelligence` для проверки IP."""

    @mcp.prompt()
    def credential_analysis() -> str:
        """Credential exposure analysis workflow."""
        return """# Анализ утечки учётных данных

## Шаг 1: Извлечение
Используйте `extract_credentials` для поиска учётных данных.

## Шаг 2: TLS проверка
Используйте `analyze_tls_handshake` для проверки шифрования.

## Шаг 3: HTTP анализ
Используйте `analyze_http_traffic` для поиска форм авторизации.

## Шаг 4: Проверка угроз
Используйте `check_threat_intelligence` для проверки целевых IP.

## Шаг 5: Рекомендации
Оцените масштаб утечки и составьте план реагирования."""

    @mcp.prompt()
    def network_baseline(interface: str = "eth0", duration: int = 30) -> str:
        """
        Establish a network baseline to understand normal traffic patterns.

        Guided workflow:
        1. Quick capture to see immediate activity
        2. Extended capture for baseline
        3. Protocol distribution analysis
        4. Conversation analysis
        """
        return f"""Establish a network baseline on interface '{interface}' for {duration} seconds.

Step 1: Run quick_capture to see immediate activity (3 seconds)
Step 2: Run capture_live_packets with extended duration
Step 3: Run get_protocol_statistics for protocol breakdown
Step 4: Run list_tcp_streams to understand active conversations

Provide a baseline report with:
- Normal traffic volume and protocol mix
- Expected communication pairs
- Baseline for future anomaly detection
- Any deviations from expected patterns"""
