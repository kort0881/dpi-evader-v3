# DPI Evader v3

**Многоуровневая система обхода DPI (Deep Packet Inspection)** с локальным SOCKS5-прокси и отвлекающим трафиком.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Возможности

- **Метод 1: Парадокс** — Decoy SYN + реальный TCP-сокет с тем же src_port. Работает через raw sockets.
- **Метод 2: Палимпсест** — NFQUEUE с задержкой и модификацией первых пакетов TCP.
- **Метод 3: Фрагментация IP** — NFQUEUE с разбивкой SYN/ClientHello на мелкие IP-фрагменты.
- **SOCKS5 прокси** — точка входа для браузеров и приложений (`127.0.0.1:1080`).
- **MorseSender** — передача данных burst-ами с пуассоновскими паузами.
- **RussianDistractor** — фоновый отвлекающий трафик (HTTP, ICMP, TCP, DoH) с адаптивной интенсивностью.
- **DecoyTunnel** — жертвенный WireGuard-туннель для отвлекающего трафика.
- **Auto-tune** — автоматический подбор параметров MorseSender.
- **Режим WSL** — автоматическое определение Windows WSL и отключение неподдерживаемых методов.

## Философия

1. **Ресурсы клиента** — не нужен дорогой VPS. Всё работает локально.
2. **Отвлекающий трафик** — постоянный поток легитимного трафика в рунете заставляет DPI тратить ресурсы на анализ «шума».
3. **Морзянка** — основной канал работает редкими импульсами с паузами, что делает его неотличимым от обычного сёрфинга.

## Установка

### Linux

```bash
git clone https://github.com/h4rdw4r3/dpi-evader-v3.git
cd dpi-evader-v3

# Основные зависимости
pip install -r requirements.txt

# Генерация конфига
sudo python3 dpi_evader.py --init-config

# Редактирование конфига
nano config.yaml

# Запуск
sudo python3 dpi_evader.py
```

### Android (Termux + Shizuku) — только метод 1

```bash
pkg install python clang libffi openssl git
pip install pyyaml requests scapy

git clone https://github.com/h4rdw4r3/dpi-evader-v3.git
cd dpi-evader-v3

chmod +x android_launcher.sh
./android_launcher.sh
```

## Использование

```bash
# Все методы для всех доменов из конфига
sudo python3 dpi_evader.py

# Один домен
sudo python3 dpi_evader.py -d youtube.com

# Через SOCKS5 прокси (браузер)
curl --socks5 127.0.0.1:1080 https://youtube.com -v

# Только метод 1 (без NFQUEUE)
sudo python3 dpi_evader.py --methods 1

# Без отвлекающего трафика
sudo python3 dpi_evader.py --no-distractor

# Автоподбор параметров
sudo python3 dpi_evader.py --auto-tune --max-tests 15

# Подробный вывод
sudo python3 dpi_evader.py -v
```

### Режим WSL

При запуске на Windows через WSL методы 2 и 3 (NFQUEUE) недоступны. Инструмент автоматически определяет WSL и переключается в режим только с методом 1:

```bash
# Автоопределение (дефолт)
sudo python3 dpi_evader.py -d youtube.com

# Принудительно WSL
sudo python3 dpi_evader.py --mode wsl -d youtube.com

# Принудительно полный Linux
sudo python3 dpi_evader.py --mode linux -d youtube.com
```

## Конфигурация

Все параметры через `config.yaml`. Генерация дефолтного:

```bash
python3 dpi_evader.py --init-config
```

### Ключевые параметры

| Параметр | Описание |
|----------|----------|
| `methods` | Список активных методов [1, 2, 3] |
| `target_domains` | Целевые домены |
| `socks5.listen_port` | Порт SOCKS5 прокси (по умолч. 1080) |
| `morse.min_pause` / `max_pause` | Диапазон пауз «морзянки» (сек) |
| `morse.poisson_lambda` | λ для распределения Пуассона |
| `distractor.adaptive_intensity` | Адаптивность по времени суток |
| `palimpsest.delay_ms` | Задержка пакетов (мс) |
| `fragment.frag_size` | Размер IP-фрагмента (байт) |
| `iptables.auto_manage` | Автоуправление правилами iptables |
| `decoy_tunnel.enabled` | Включить жертвенный туннель |

### Auto-tune

Автоподбор параметров MorseSender (chunk size, паузы, lambda) через реальное тестирование методом 1:

```bash
sudo python3 dpi_evader.py --auto-tune --max-tests 20
```

После тестирования предложит сохранить лучшую комбинацию в config.yaml.

## Тестирование

```bash
python -m pytest tests/ -v
```

## Требования

- Python 3.9+
- Linux (для методов 2, 3 — iptables + NFQUEUE)
- root (для raw sockets, iptables и NFQUEUE)
- `scapy`, `requests`, `PyYAML`
- `netfilterqueue` (опционально, только для методов 2, 3)

## Структура проекта

```
dpi-evader-v3/
├── dpi_evader.py          # Основной скрипт (все классы)
├── config.yaml            # Конфигурация
├── requirements.txt       # Зависимости
├── .gitignore             # Исключения Git
├── README.md              # Документация
├── LICENSE                # MIT лицензия
├── android_launcher.sh    # Запуск на Android
├── test_socks5.py         # Тестовый SOCKS5 сервер
└── tests/
    ├── __init__.py
    ├── test_morse_sender.py
    ├── test_distractor.py
    └── test_methods.py
```

## Лицензия

MIT License — см. файл [LICENSE](LICENSE).
