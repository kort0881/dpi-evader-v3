#!/usr/bin/env python3
"""
DPI Evader v3 — Многоуровневый обход DPI с морзянкой и отвлекающим трафиком.

Методы обхода:
  [1] Парадокс — decoy raw-пакет -> реальный TCP сокет с тем же src_port
  [2] Палимпсест — NFQUEUE с задержкой и модификацией первых пакетов TCP
  [3] Фрагментация — NFQUEUE с IP-фрагментацией handshake-пакетов

  MorseSender — burst-отправка данных (импульсами, как азбука Морзе)
  RussianDistractor — фоновый отвлекающий трафик (HTTP, ICMP, TCP, DoH)

Зависимости:
  pip install scapy requests pyyaml netfilterqueue
"""

import argparse
import atexit
import hashlib
import logging
import math
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import yaml

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, DNS, DNSQR,
        Raw, send, fragment, raw, conf as scapy_conf
    )
    scapy_conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from netfilterqueue import NetfilterQueue
    HAS_NFQUEUE = True
except ImportError:
    HAS_NFQUEUE = False

# ──────────────────────────────────────────────
# Логирование
# ──────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("DPIEvader")

# ──────────────────────────────────────────────
# Конфиг
# ──────────────────────────────────────────────

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

DEFAULT_CONFIG = {
    "mode": "auto",
    "methods": [1, 2, 3],
    "target_domains": [
        "example.com",
        "youtube.com",
    ],
    "target_ips": [],
    "target_port": 443,
    "listen_host": "0.0.0.0",
    "listen_port": 1080,
    "interface": "eth0",
    "morse": {
        "enabled": True,
        "min_chunk_size": 64,
        "max_chunk_size": 512,
        "min_pause": 2.0,
        "max_pause": 15.0,
        "keepalive_interval": 30,
        "keepalive_enabled": True,
        "poisson_lambda": 5.0,
    },
    "distractor": {
        "enabled": True,
        "sites": [
            "https://yandex.ru",
            "https://mail.ru",
            "https://gosuslugi.ru",
            "https://lenta.ru",
            "https://rbc.ru",
            "https://vk.com",
            "https://ok.ru",
            "https://ria.ru",
            "https://tass.ru",
            "https://rambler.ru",
        ],
        "min_pause": 10,
        "max_pause": 180,
        "icmp_enabled": True,
        "icmp_targets": [
            "77.88.8.8",      # Yandex DNS
            "77.88.8.1",
            "8.8.8.8",
            "1.1.1.1",
        ],
        "tcp_halfopen_enabled": True,
        "tcp_halfopen_targets": [
            "yandex.ru:443",
            "mail.ru:443",
            "vk.com:443",
        ],
        "tcp_halfopen_hold_min": 30,
        "tcp_halfopen_hold_max": 60,
        "doh_noise_enabled": True,
        "doh_resolvers": [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://dns.google/dns-query",
        ],
        "doh_noise_domains": [
            "yandex.ru", "mail.ru", "google.com", "facebook.com",
            "twitter.com", "instagram.com", "tiktok.com", "reddit.com",
            "wikipedia.org", "amazon.com", "netflix.com", "spotify.com",
        ],
        "adaptive_intensity": True,
        # Множители интенсивности по часам (0-23)
        # Вечер (18-23) — больше, Ночь (0-6) — меньше
        "intensity_schedule": {
            "night": {"hours": [0,1,2,3,4,5,6], "multiplier": 0.3},
            "morning": {"hours": [7,8,9,10,11], "multiplier": 0.7},
            "day": {"hours": [12,13,14,15,16,17], "multiplier": 1.0},
            "evening": {"hours": [18,19,20,21,22,23], "multiplier": 1.5},
        },
    },
    "palimpsest": {
        "nfqueue_num": 100,
        "delay_ms": 50,
        "max_delayed_packets": 20,
        "modify_syn_options": True,
    },
    "fragment": {
        "nfqueue_num": 101,
        "frag_size": 8,
        "target_phases": ["syn", "syn_ack", "client_hello"],
    },
    "iptables": {
        "auto_manage": True,
        "cleanup_on_exit": True,
    },
    "decoy_tunnel": {
        "enabled": False,
        "type": "wireguard",
        "interface": "wg0",
        "server": "vps.ru",
        "port": 51820,
        "allowed_ips": ["0.0.0.0/0"],
        "local_address": "10.0.0.2/24",
        "private_key": "",
        "peer_public_key": "",
        "endpoint_ip": "",
        "health_check_interval": 60,
        "health_check_url": "https://yandex.ru",
        "auto_restart": True,
        "restart_grace_period": 5,
        "traffic": "only_distractor",
        "mark": 0xdec0,
    },
    "socks5": {
        "enabled": True,
        "listen_host": "127.0.0.1",
        "listen_port": 1080,
    },
}


def load_config(path=None):
    """Загрузить конфиг с глубоким слиянием с дефолтами."""
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}
    return _deep_merge(DEFAULT_CONFIG, cfg)


def _deep_merge(base: dict, override: dict) -> dict:
    """Рекурсивное слияние словарей."""
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def save_default_config(path=None):
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    with open(path, "w") as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True)
    logger.info(f"Конфиг по умолчанию сохранён: {path}")


# ──────────────────────────────────────────────
# Утилиты: iptables
# ──────────────────────────────────────────────

class IptablesManager:
    """
    Управление правилами iptables для NFQUEUE.
    Автоматически добавляет/удаляет правила.
    Хранит список добавленных правил для cleanup.
    """

    def __init__(self, auto_manage=True, cleanup_on_exit=True):
        self.auto_manage = auto_manage
        self.cleanup_on_exit = cleanup_on_exit
        self.rules_added = []  # список (chain, rule_args) для откатки
        if cleanup_on_exit:
            atexit.register(self.cleanup)

    def _run_iptables(self, action: str, chain: str, rule_args: list) -> bool:
        """Выполнить команду iptables."""
        cmd = ["iptables", action, chain] + rule_args
        logger.debug(f"iptables: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.warning(f"iptables error: {result.stderr.strip()}")
                return False
            return True
        except FileNotFoundError:
            logger.error("iptables не найден. Установите iptables.")
            return False
        except subprocess.TimeoutExpired:
            logger.error("iptables: таймаут выполнения")
            return False

    def add_nfqueue_rule(self, dst_ip: str, dst_port: int, queue_num: int,
                         protocol: str = "tcp", chain: str = "OUTPUT"):
        """Добавить правило для перенаправления пакетов в NFQUEUE."""
        if not self.auto_manage:
            logger.info(f"Ручной режим: добавьте правило iptables -A {chain} "
                       f"-d {dst_ip} -p {protocol} --dport {dst_port} "
                       f"-j NFQUEUE --queue-num {queue_num}")
            return False

        rule_args = [
            "-d", dst_ip,
            "-p", protocol,
            "--dport", str(dst_port),
            "-j", "NFQUEUE",
            "--queue-num", str(queue_num),
        ]

        # Проверяем, нет ли уже такого правила
        if self._run_iptables("-C", chain, rule_args):
            logger.debug(f"Правило уже существует: {chain} -> NFQUEUE {queue_num}")
            return True

        if self._run_iptables("-A", chain, rule_args):
            self.rules_added.append((chain, rule_args))
            logger.info(f"iptables: добавлено правило {chain} -d {dst_ip} "
                       f"--dport {dst_port} -> NFQUEUE {queue_num}")
            return True
        return False

    def add_input_nfqueue_rule(self, src_ip: str, src_port: int, queue_num: int,
                                protocol: str = "tcp"):
        """Правило для входящих пакетов (ответы от сервера)."""
        if not self.auto_manage:
            return False

        rule_args = [
            "-s", src_ip,
            "-p", protocol,
            "--sport", str(src_port),
            "-j", "NFQUEUE",
            "--queue-num", str(queue_num),
        ]

        if self._run_iptables("-C", "INPUT", rule_args):
            return True

        if self._run_iptables("-A", "INPUT", rule_args):
            self.rules_added.append(("INPUT", rule_args))
            return True
        return False

    def cleanup(self):
        """Удалить все добавленные правила."""
        for chain, rule_args in reversed(self.rules_added):
            self._run_iptables("-D", chain, rule_args)
            logger.debug(f"iptables: удалено правило из {chain}")
        self.rules_added.clear()
        logger.info("iptables: все правила очищены")


# ──────────────────────────────────────────────
# Утилиты: адаптивная интенсивность
# ──────────────────────────────────────────────

class IntensityController:
    """
    Контролирует интенсивность отвлекающего трафика
    в зависимости от времени суток.
    """

    def __init__(self, schedule: dict):
        self.schedule = schedule
        self._build_hour_map()

    def _build_hour_map(self):
        """Построить маппинг час -> множитель."""
        self.hour_multiplier = {}
        for period_name, period_cfg in self.schedule.items():
            for hour in period_cfg["hours"]:
                self.hour_multiplier[hour] = period_cfg["multiplier"]
        # Заполнить пропущенные часы множителем 1.0
        for h in range(24):
            if h not in self.hour_multiplier:
                self.hour_multiplier[h] = 1.0

    def get_multiplier(self) -> float:
        """Получить текущий множитель интенсивности."""
        current_hour = datetime.now().hour
        return self.hour_multiplier.get(current_hour, 1.0)

    def adjust_pause(self, base_min: float, base_max: float) -> tuple:
        """Скорректировать паузу: при высокой интенсивности — короче."""
        mult = self.get_multiplier()
        if mult <= 0:
            mult = 0.1
        # Инвертируем: высокий множитель = короткие паузы
        adjusted_min = base_min / mult
        adjusted_max = base_max / mult
        return adjusted_min, adjusted_max


# ──────────────────────────────────────────────
# MorseSender — улучшенная burst-отправка
# ──────────────────────────────────────────────

class MorseSender:
    """
    Burst-отправка данных через сокет, имитирующая азбуку Морзе:
    - Случайный размер чанков (min_chunk..max_chunk)
    - Паузы по распределению Пуассона
    - Keep-alive пустые пакеты для поддержания соединения
    """

    def __init__(self, real_sock,
                 min_chunk_size=64, max_chunk_size=512,
                 min_pause=2.0, max_pause=15.0,
                 poisson_lambda=5.0,
                 keepalive_enabled=True, keepalive_interval=30):
        self.sock = real_sock
        self.min_chunk = min_chunk_size
        self.max_chunk = max_chunk_size
        self.min_pause = min_pause
        self.max_pause = max_pause
        self.poisson_lambda = poisson_lambda
        self.keepalive_enabled = keepalive_enabled
        self.keepalive_interval = keepalive_interval

        self.buffer = b""
        self.lock = threading.Lock()
        self.running = True
        self.last_send_time = time.time()

        self.stats = {"chunks_sent": 0, "bytes_sent": 0, "keepalives": 0}

        self.worker = threading.Thread(target=self._send_loop, daemon=True)
        self.worker.name = "morse-send"
        self.worker.start()

        self.keepalive_worker = None
        if keepalive_enabled:
            self.keepalive_worker = threading.Thread(
                target=self._keepalive_loop, daemon=True
            )
            self.keepalive_worker.name = "morse-keepalive"
            self.keepalive_worker.start()

        # Включаем TCP keep-alive на уровне ядра вместо TLS-keepalive пакетов
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Начинать keepalive после 60s простоя (переопределится keepalive_interval)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, keepalive_interval)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except (AttributeError, OSError):
            pass  # Не все платформы поддерживают эти опции

        logger.debug(
            f"MorseSender: chunk={min_chunk_size}-{max_chunk_size}B, "
            f"pause={min_pause}-{max_pause}s, λ={poisson_lambda}"
        )

    def send(self, data: bytes):
        """Добавить данные в буфер для burst-отправки."""
        with self.lock:
            self.buffer += data

    def _poisson_pause(self) -> float:
        """
        Генерировать паузу по распределению Пуассона (экспоненциальное).
        Ограничиваем значениями min_pause..max_pause.
        """
        # Экспоненциальное распределение — интервалы между событиями Пуассона
        raw = random.expovariate(1.0 / self.poisson_lambda)
        return max(self.min_pause, min(raw, self.max_pause))

    def _random_chunk_size(self) -> int:
        """Случайный размер чанка."""
        return random.randint(self.min_chunk, self.max_chunk)

    def _send_loop(self):
        while self.running:
            chunk = None
            chunk_size = self._random_chunk_size()

            with self.lock:
                if len(self.buffer) >= chunk_size:
                    chunk = self.buffer[:chunk_size]
                    self.buffer = self.buffer[chunk_size:]
                elif len(self.buffer) > 0:
                    # Если данных меньше чем chunk_size, но есть что отправить
                    # Отправляем с вероятностью 30% (имитация коротких точек)
                    if random.random() < 0.3:
                        chunk = self.buffer
                        self.buffer = b""

            if chunk:
                try:
                    self.sock.sendall(chunk)
                    self.last_send_time = time.time()
                    self.stats["chunks_sent"] += 1
                    self.stats["bytes_sent"] += len(chunk)
                    logger.debug(
                        f"Morse: ─── {len(chunk)}B "
                        f"(всего: {self.stats['bytes_sent']}B, "
                        f"чанков: {self.stats['chunks_sent']})"
                    )
                except Exception as e:
                    logger.error(f"Morse send error: {e}")
                    self.running = False
                    break

            # Пауза по Пуассону
            pause = self._poisson_pause()
            time.sleep(pause)

    def _keepalive_loop(self):
        """Отправка пустого TLS application data record для удержания соединения."""
        while self.running:
            time.sleep(self.keepalive_interval)
            elapsed = time.time() - self.last_send_time
            if elapsed >= self.keepalive_interval and self.running:
                try:
                    # Пустой TLS application data record (ContentType=23)
                    # 0x17 = Application Data, 0x0303 = TLS 1.2, длина 0
                    self.sock.sendall(b"\x17\x03\x03\x00\x00")
                    self.last_send_time = time.time()
                    self.stats["keepalives"] += 1
                    logger.debug(f"Morse: keep-alive #{self.stats['keepalives']}")
                except Exception as e:
                    logger.debug(f"Morse keep-alive error: {e}")

    def flush(self):
        """Отправить всё оставшееся и закрыть."""
        with self.lock:
            remaining = self.buffer
            self.buffer = b""
        if remaining:
            try:
                self.sock.sendall(remaining)
                self.stats["bytes_sent"] += len(remaining)
                logger.debug(f"Morse: flush {len(remaining)}B")
            except Exception as e:
                logger.error(f"Morse flush error: {e}")
        self.close()

    def close(self):
        self.running = False
        # join потоков с таймаутом
        for t in [self.worker, self.keepalive_worker]:
            if t and t.is_alive():
                t.join(timeout=3)
        try:
            self.sock.close()
        except Exception:
            pass

    def get_stats(self) -> dict:
        return self.stats.copy()


# ──────────────────────────────────────────────
# RussianDistractor — расширенный отвлекающий трафик
# ──────────────────────────────────────────────

class RussianDistractor:
    """
    Фоновый генератор отвлекающего трафика:
    1. HTTP-запросы к российским сайтам (разные UA, пути, заголовки)
    2. ICMP-пустышки (ping случайных IP)
    3. TCP полуоткрытые соединения (connect без данных, держать 30-60с)
    4. DNS-over-HTTPS шум (запросы случайных доменов)
    5. Адаптивная интенсивность (вечером чаще, ночью реже)
    """

    def __init__(self, config: dict):
        dcfg = config["distractor"]
        self.sites = dcfg["sites"]
        self.min_pause = dcfg["min_pause"]
        self.max_pause = dcfg["max_pause"]

        # ICMP
        self.icmp_enabled = dcfg.get("icmp_enabled", False)
        self.icmp_targets = dcfg.get("icmp_targets", [])

        # TCP half-open
        self.tcp_halfopen_enabled = dcfg.get("tcp_halfopen_enabled", False)
        self.tcp_halfopen_targets = dcfg.get("tcp_halfopen_targets", [])
        self.tcp_hold_min = dcfg.get("tcp_halfopen_hold_min", 30)
        self.tcp_hold_max = dcfg.get("tcp_halfopen_hold_max", 60)

        # DoH noise
        self.doh_enabled = dcfg.get("doh_noise_enabled", False)
        self.doh_resolvers = dcfg.get("doh_resolvers", [])
        self.doh_domains = dcfg.get("doh_noise_domains", [])

        # Адаптивная интенсивность
        self.adaptive = dcfg.get("adaptive_intensity", False)
        if self.adaptive:
            self.intensity = IntensityController(
                dcfg.get("intensity_schedule", DEFAULT_CONFIG["distractor"]["intensity_schedule"])
            )
        else:
            self.intensity = None

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
        ]
        self.paths = [
            "/", "/news", "/search?q=test", "/?from=main", "/settings",
            "/about", "/contacts", "/help", "/sitemap.xml",
            f"/?rnd={random.randint(1000, 9999)}",
            f"/search?q={''.join(random.choices('абвгдежзиклмнопрстуфхцчшщэюя', k=5))}",
        ]

        self.running = True
        self.halfopen_sockets = []  # Отслеживание полуоткрытых сокетов
        self.stats = defaultdict(int)

        # Запуск воркеров
        self.workers = []
        self._start_workers()

        logger.info(
            f"Distractor запущен: HTTP={len(self.sites)} сайтов, "
            f"ICMP={'вкл' if self.icmp_enabled else 'выкл'}, "
            f"TCP-halfopen={'вкл' if self.tcp_halfopen_enabled else 'выкл'}, "
            f"DoH={'вкл' if self.doh_enabled else 'выкл'}, "
            f"Adaptive={'вкл' if self.adaptive else 'выкл'}"
        )

    def _start_workers(self):
        # HTTP-шум
        t = threading.Thread(target=self._http_loop, daemon=True, name="distractor-http")
        t.start()
        self.workers.append(t)

        # ICMP-шум
        if self.icmp_enabled and HAS_SCAPY:
            t = threading.Thread(target=self._icmp_loop, daemon=True, name="distractor-icmp")
            t.start()
            self.workers.append(t)
        elif self.icmp_enabled:
            logger.warning("ICMP distractor: scapy не установлен, используем системный ping")
            t = threading.Thread(target=self._icmp_system_loop, daemon=True, name="distractor-icmp-sys")
            t.start()
            self.workers.append(t)

        # TCP half-open
        if self.tcp_halfopen_enabled:
            t = threading.Thread(target=self._tcp_halfopen_loop, daemon=True, name="distractor-tcp")
            t.start()
            self.workers.append(t)

        # DoH noise
        if self.doh_enabled and HAS_REQUESTS:
            t = threading.Thread(target=self._doh_loop, daemon=True, name="distractor-doh")
            t.start()
            self.workers.append(t)

    def _get_adjusted_pause(self) -> float:
        """Получить паузу с учётом адаптивной интенсивности."""
        if self.intensity:
            adj_min, adj_max = self.intensity.adjust_pause(self.min_pause, self.max_pause)
        else:
            adj_min, adj_max = self.min_pause, self.max_pause
        return random.uniform(adj_min, adj_max)

    # ── HTTP-шум ──

    def _http_loop(self):
        if not HAS_REQUESTS:
            logger.error("Distractor HTTP: requests не установлен")
            return

        session = requests.Session()
        session.verify = False

        while self.running:
            site = random.choice(self.sites)
            path = random.choice(self.paths)
            url = site.rstrip("/") + path
            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.5",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Cache-Control": random.choice(["no-cache", "max-age=0", ""]),
                "Pragma": "no-cache",
                "DNT": random.choice(["1", "0"]),
            }
            # Иногда Range header
            if random.random() > 0.7:
                headers["Range"] = f"bytes=0-{random.randint(512, 8192)}"
            # Иногда Referer
            if random.random() > 0.5:
                headers["Referer"] = random.choice(self.sites)

            try:
                resp = session.get(url, headers=headers, timeout=10, allow_redirects=True)
                self.stats["http_requests"] += 1
                logger.debug(f"Distractor HTTP: {url} -> {resp.status_code} ({len(resp.content)}B)")
            except Exception as e:
                self.stats["http_errors"] += 1
                logger.debug(f"Distractor HTTP: {url} -> {e}")

            time.sleep(self._get_adjusted_pause())

    def get_stats(self) -> dict:
        return dict(self.stats)

    def stop(self):
        self.running = False
        # Закрыть все полуоткрытые сокеты
        for sock in self.halfopen_sockets:
            try:
                sock.close()
            except Exception:
                pass
        self.halfopen_sockets.clear()
        # join воркеров
        for t in self.workers:
            if t.is_alive():
                t.join(timeout=3)
        logger.info(f"Distractor остановлен. Статистика: {dict(self.stats)}")


# ──────────────────────────────────────────────
# DecoyTunnel — жертвенный туннель-приманка
# ──────────────────────────────────────────────

class DecoyTunnel:
    """
    Жертвенный туннель (sacrificial/decoy tunnel).

    Поднимает явный, легко детектируемый VPN-туннель (WireGuard),
    по которому идёт ТОЛЬКО легитимный отвлекающий трафик (RussianDistractor).
    ТСПУ видит этот туннель, анализирует его, убеждается что он безопасен
    и переключает внимание. Реальный трафик идёт другим путём.

    Фичи:
    - Подъём/опускание WireGuard-интерфейса через wg-quick
    - Маркировка пакетов отвлекающего трафика (fwmark)
    - Маршрутизация: decoy-трафик -> туннель, остальное -> напрямую
    - Health-check: периодическая проверка доступности туннеля
    - Auto-restart при падении
    - Graceful shutdown
    """

    def __init__(self, config: dict):
        self.config = config
        dcfg = config["decoy_tunnel"]
        self.enabled = dcfg["enabled"]
        self.tunnel_type = dcfg["type"]
        self.iface = dcfg["interface"]
        self.server = dcfg["server"]
        self.port = dcfg["port"]
        self.allowed_ips = dcfg["allowed_ips"]
        self.local_address = dcfg["local_address"]
        self.private_key = dcfg["private_key"]
        self.peer_pubkey = dcfg["peer_public_key"]
        self.endpoint_ip = dcfg["endpoint_ip"]
        self.health_check_url = dcfg["health_check_url"]
        self.health_check_interval = dcfg["health_check_interval"]
        self.auto_restart = dcfg["auto_restart"]
        self.restart_grace = dcfg["restart_grace_period"]
        self.mark = dcfg["mark"]

        self.running = False
        self.healthy = False
        self.worker = None
        self._wg_config_path = None
        self._rules_added = []

    def _check_dependencies(self) -> bool:
        """Проверить, установлен ли WireGuard-tools."""
        try:
            subprocess.run(["wg", "--version"], capture_output=True, timeout=5)
            subprocess.run(["wg-quick", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.error("DecoyTunnel: wg/wg-quick не найдены. Установите wireguard-tools.")
            return False

    def _generate_wg_config(self) -> str:
        """Сгенерировать конфиг WireGuard для wg-quick."""
        dcfg = self.config["decoy_tunnel"]
        lines = [
            "[Interface]",
            f"PrivateKey = {dcfg['private_key']}",
            f"Address = {dcfg['local_address']}",
            f"DNS = 77.88.8.8, 77.88.8.1",
            f"Table = auto",
            f"FwMark = {self.mark}",
            "",
            "[Peer]",
            f"PublicKey = {dcfg['peer_public_key']}",
            f"Endpoint = {dcfg.get('endpoint_ip') or dcfg['server']}:{dcfg['port']}",
            f"AllowedIPs = {', '.join(dcfg['allowed_ips'])}",
            "PersistentKeepalive = 25",
            "",
        ]
        return "\n".join(lines)

    def start(self):
        """Поднять жертвенный туннель."""
        if not self.enabled:
            logger.info("DecoyTunnel: отключён в конфиге")
            return False

        if not self._check_dependencies():
            return False

        dcfg = self.config["decoy_tunnel"]
        if not dcfg["private_key"] or not dcfg["peer_public_key"]:
            logger.error("DecoyTunnel: не указаны private_key и peer_public_key в config.yaml")
            return False

        logger.info(f"DecoyTunnel: поднимаю {self.tunnel_type}-туннель {self.iface} -> {self.server}:{self.port}")

        # Генерируем и сохраняем конфиг
        wg_conf = self._generate_wg_config()
        conf_path = Path(f"/etc/wireguard/{self.iface}.conf")
        try:
            # Сначала пробуем /etc/wireguard/
            conf_path.write_text(wg_conf)
        except PermissionError:
            # Fallback: /tmp/
            conf_path = Path(f"/tmp/{self.iface}.conf")
            conf_path.write_text(wg_conf)
            logger.warning(f"DecoyTunnel: нет прав на /etc/wireguard/, использую {conf_path}")

        self._wg_config_path = conf_path

        # Поднимаем интерфейс
        try:
            subprocess.run(
                ["wg-quick", "up", str(conf_path)],
                capture_output=True, text=True, timeout=30
            )
            logger.info(f"DecoyTunnel: {self.iface} поднят")
        except subprocess.CalledProcessError as e:
            logger.error(f"DecoyTunnel: ошибка wg-quick up: {e}")
            return False
        except FileNotFoundError:
            logger.error("DecoyTunnel: wg-quick не найден")
            return False

        # Маршрутизация через fwmark:
        # Пакеты с меткой self.mark идут через туннель
        # Остальные — напрямую (включая настоящий трафик)
        self._setup_routing()

        self.running = True

        # Health-check воркер
        self.worker = threading.Thread(target=self._health_loop, daemon=True, name="decoy-health")
        self.worker.start()

        logger.info(f"DecoyTunnel: запущен и работает")
        return True

    def _setup_routing(self):
        """Настроить маршрутизацию через fwmark."""
        try:
            # Правило: пакеты с fwmark -> таблица decoy
            subprocess.run(
                ["ip", "rule", "add", f"fwmark", str(self.mark), "table", "decoy"],
                capture_output=True, timeout=5
            )
            # Маршрут: всё через туннель
            subprocess.run(
                ["ip", "route", "add", "default", "dev", self.iface, "table", "decoy"],
                capture_output=True, timeout=5
            )
            self._rules_added.append("ip rule fwmark")
            self._rules_added.append("ip route default via tunnel")
            logger.debug("DecoyTunnel: маршрутизация через fwmark настроена")
        except subprocess.TimeoutExpired:
            logger.warning("DecoyTunnel: timeout при настройке маршрутизации")

    def _health_loop(self):
        """Периодическая проверка туннеля."""
        while self.running:
            time.sleep(self.health_check_interval)
            healthy = self._check_health()
            if healthy:
                if not self.healthy:
                    logger.info("DecoyTunnel: здоровье восстановлено")
                self.healthy = True
            else:
                logger.warning("DecoyTunnel: health-check не прошёл!")
                self.healthy = False
                if self.auto_restart:
                    logger.info("DecoyTunnel: перезапуск...")
                    self._teardown()
                    time.sleep(self.restart_grace)
                    self.start()

    def _check_health(self) -> bool:
        """Проверить, жив ли туннель."""
        # Способ 1: wg show
        try:
            r = subprocess.run(
                ["wg", "show", self.iface], capture_output=True, text=True, timeout=5
            )
            if "latest handshake" in r.stdout:
                return True
        except Exception:
            pass

        # Способ 2: ping через туннель
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "3", self.server],
                capture_output=True, timeout=5
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass

        # Способ 3: HTTP check
        if HAS_REQUESTS and self.health_check_url:
            try:
                resp = requests.get(self.health_check_url, timeout=5, verify=False)
                return resp.status_code == 200
            except Exception:
                pass

        return False

    def route_distractor_through_tunnel(self, distractor: RussianDistractor):
        """
        Перенаправить отвлекающий трафик через жертвенный туннель.
        Использует iptables fwmark для маркировки пакетов от нашего процесса.
        """
        if not self.running:
            return

        try:
            my_pid = os.getpid()
            # Маркируем все пакеты от PID нашего процесса меткой self.mark
            # Правило в mangle/OUTPUT: пакеты от нашего процесса -> fwmark
            subprocess.run(
                ["iptables", "-t", "mangle", "-A", "OUTPUT",
                 "-m", "owner", "--pid-owner", str(my_pid),
                 "-j", "MARK", "--set-mark", str(self.mark)],
                capture_output=True, timeout=5, check=True
            )
            self._rules_added.append(("mangle", "OUTPUT", my_pid))
            logger.info(f"DecoyTunnel: трафик процесса {my_pid} помечен fwmark={self.mark}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"DecoyTunnel: не удалось настроить iptables fwmark: {e}")
        except FileNotFoundError:
            logger.warning("DecoyTunnel: iptables не найден, fwmark не настроен")

    def _teardown(self):
        """Опустить туннель и очистить маршрутизацию."""
        try:
            subprocess.run(
                ["wg-quick", "down", str(self._wg_config_path)],
                capture_output=True, timeout=30
            )
        except Exception:
            pass

        # Удаляем правила маршрутизации и iptables
        for rule in reversed(self._rules_added):
            try:
                if isinstance(rule, tuple) and rule[0] == "mangle":
                    # iptables mangle правило — удалить по pid
                    subprocess.run(
                        ["iptables", "-t", "mangle", "-D", "OUTPUT",
                         "-m", "owner", "--pid-owner", str(rule[2]),
                         "-j", "MARK", "--set-mark", str(self.mark)],
                        capture_output=True, timeout=5
                    )
                elif "fwmark" in rule:
                    subprocess.run(["ip", "rule", "del", f"fwmark", str(self.mark)],
                                   capture_output=True, timeout=5)
                elif "route" in rule:
                    subprocess.run(["ip", "route", "del", "default", "dev", self.iface, "table", "decoy"],
                                   capture_output=True, timeout=5)
            except Exception:
                pass
        self._rules_added.clear()

    def stop(self):
        """Остановить жертвенный туннель."""
        logger.info("DecoyTunnel: остановка...")
        self.running = False
        self._teardown()
        logger.info("DecoyTunnel: остановлен")


# ──────────────────────────────────────────────
# 3. Парадокс (Метод 1) — decoy + TCP сокет
# ──────────────────────────────────────────────


# ──────────────────────────────────────────────
# Метод 1: Парадокс — decoy + реальный TCP
# ──────────────────────────────────────────────

class MethodParadox:
    """
    Метод «Парадокс»:
    1. Отправляем decoy TCP SYN с мусором через raw socket
    2. Устанавливаем реальный TCP-сокет с тем же src_port
    3. Возвращаем MorseSender для burst-отправки
    """

    def __init__(self, config: dict):
        self.config = config
        self.ip_cache = {}

    def _resolve(self, domain: str) -> str:
        if domain in self.ip_cache:
            return self.ip_cache[domain]
        ip = socket.gethostbyname(domain)
        self.ip_cache[domain] = ip
        return ip

    def _compute_tcp_checksum(self, src_ip: bytes, dst_ip: bytes,
                               tcp_header: bytes, payload: bytes = b"") -> int:
        """Вычислить TCP чексумму с pseudo-header."""
        # Pseudo-header
        tcp_length = len(tcp_header) + len(payload)
        pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0,
                             socket.IPPROTO_TCP, tcp_length)
        data = pseudo + tcp_header + payload
        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF

    def _send_decoy(self, dst_ip: str, dst_port: int, src_port: int):
        """Отправить decoy TCP SYN с мусором."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Определяем наш IP
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                temp_sock.connect((dst_ip, 80))
                src_ip = temp_sock.getsockname()[0]
            finally:
                temp_sock.close()

            src_ip_bytes = socket.inet_aton(src_ip)
            dst_ip_bytes = socket.inet_aton(dst_ip)

            # IP Header
            ip_ihl = 5
            ip_ver = 4
            ip_tos = 0
            ip_id = random.randint(0, 65535)
            ip_frag_off = 0
            ip_ttl = random.randint(3, 8)  # Маленький TTL — пакет умрёт в пути
            ip_proto = socket.IPPROTO_TCP

            # Decoy payload
            decoy_data = os.urandom(random.randint(16, 128))

            ip_tot_len = 20 + 20 + len(decoy_data)

            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len,
                ip_id, ip_frag_off, ip_ttl, ip_proto, 0,
                src_ip_bytes, dst_ip_bytes,
            )

            # TCP Header
            seq = random.randint(0, 2**32 - 1)
            ack_seq = 0
            data_offset = 5
            tcp_flags = 0x02  # SYN
            window = 65535
            urg_ptr = 0

            tcp_header_no_checksum = struct.pack(
                "!HHLLBBHHH",
                src_port, dst_port, seq, ack_seq,
                (data_offset << 4), tcp_flags,
                window, 0, urg_ptr,
            )

            tcp_checksum = self._compute_tcp_checksum(
                src_ip_bytes, dst_ip_bytes,
                tcp_header_no_checksum, decoy_data
            )

            tcp_header = struct.pack(
                "!HHLLBBHHH",
                src_port, dst_port, seq, ack_seq,
                (data_offset << 4), tcp_flags,
                window, tcp_checksum, urg_ptr,
            )

            packet = ip_header + tcp_header + decoy_data
            sock.sendto(packet, (dst_ip, 0))
            sock.close()
            logger.debug(
                f"Paradox: decoy SYN -> {dst_ip}:{dst_port} "
                f"(src_port={src_port}, TTL={ip_ttl}, payload={len(decoy_data)}B)"
            )
        except PermissionError:
            logger.error(
                "Paradox: требуются root-права для raw socket. "
                "Запустите с sudo или через Shizuku."
            )
            raise
        except Exception as e:
            logger.error(f"Paradox: ошибка decoy: {e}")
            raise

    def connect(self, domain: str, port: int) -> MorseSender:
        """Установить соединение методом Парадокс."""
        mcfg = self.config["morse"]
        dst_ip = self._resolve(domain)
        src_port = random.randint(10000, 60000)

        logger.info(f"Paradox: {domain} ({dst_ip}:{port}), src_port={src_port}")

        # Шаг 1: Decoy
        self._send_decoy(dst_ip, port, src_port)
        time.sleep(random.uniform(0.05, 0.3))

        # Шаг 2: Реальный сокет
        real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        real_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            real_sock.bind(("0.0.0.0", src_port))
        except OSError as e:
            logger.warning(f"Paradox: bind {src_port} failed ({e}), random port")
            real_sock.bind(("0.0.0.0", 0))

        real_sock.settimeout(30)
        try:
            real_sock.connect((dst_ip, port))
            logger.info(f"Paradox: TCP connected {domain}:{port}")
        except Exception as e:
            logger.error(f"Paradox: connect failed: {e}")
            real_sock.close()
            raise

        # Шаг 3: MorseSender
        morse = MorseSender(
            real_sock,
            min_chunk_size=mcfg.get("min_chunk_size", 64),
            max_chunk_size=mcfg.get("max_chunk_size", 512),
            min_pause=mcfg["min_pause"],
            max_pause=mcfg["max_pause"],
            poisson_lambda=mcfg.get("poisson_lambda", 5.0),
            keepalive_enabled=mcfg.get("keepalive_enabled", True),
            keepalive_interval=mcfg.get("keepalive_interval", 30),
        )
        return morse


# ──────────────────────────────────────────────
# Метод 2: Палимпсест — задержка и модификация через NFQUEUE
# ──────────────────────────────────────────────

class MethodPalimpsest:
    """
    Метод «Палимпсест» (TCP Palimpsest):
    Перехватывает исходящие TCP-пакеты через NFQUEUE и:
    1. Задерживает первые N пакетов нового соединения
    2. Модифицирует TCP-опции SYN (window scale, timestamps)
    3. Для ClientHello: задерживает и отправляет с изменённым timing

    Создаёт эффект «палимпсеста» — DPI видит наложение потоков.
    """

    def __init__(self, config: dict, iptables_mgr: IptablesManager):
        self.config = config
        self.pcfg = config["palimpsest"]
        self.iptables = iptables_mgr

        self.queue_num = self.pcfg["nfqueue_num"]
        self.delay_ms = self.pcfg["delay_ms"]
        self.max_delayed = self.pcfg["max_delayed_packets"]
        self.modify_syn = self.pcfg.get("modify_syn_options", True)

        # Отслеживание состояний TCP-соединений
        # key: (src_ip, src_port, dst_ip, dst_port) -> state dict
        self.connections = defaultdict(lambda: {
            "packet_count": 0,
            "syn_seen": False,
            "delayed_queue": [],
        })
        self.lock = threading.Lock()
        self.running = False
        self.nfq = None
        self.thread = None

    def _packet_callback(self, pkt):
        """Обработчик пакетов из NFQUEUE."""
        try:
            if not HAS_SCAPY:
                pkt.accept()
                return

            scapy_pkt = IP(pkt.get_payload())

            if not scapy_pkt.haslayer(TCP):
                pkt.accept()
                return

            tcp = scapy_pkt[TCP]
            conn_key = (
                scapy_pkt.src, tcp.sport,
                scapy_pkt.dst, tcp.dport
            )

            with self.lock:
                conn = self.connections[conn_key]
                conn["packet_count"] += 1

                # SYN-пакет — модификация опций
                if tcp.flags & 0x02 and not tcp.flags & 0x10:  # SYN, not ACK
                    conn["syn_seen"] = True
                    if self.modify_syn:
                        scapy_pkt = self._modify_syn_options(scapy_pkt)
                        pkt.set_payload(raw(scapy_pkt))
                        logger.debug(f"Palimpsest: SYN modified {conn_key}")

                # Задержка первых пакетов через таймеры (один поток на все)
                if conn["packet_count"] <= self.max_delayed:
                    delay = self.delay_ms / 1000.0
                    delay += random.uniform(0, delay * 0.5)  # Джиттер

                    timer = threading.Timer(delay, lambda p=pkt: self._delayed_accept(p))
                    timer.daemon = True
                    timer.start()
                    logger.debug(
                        f"Palimpsest: delayed pkt #{conn['packet_count']} "
                        f"by {delay*1000:.0f}ms {conn_key}"
                    )
                    return  # Не вызываем accept — таймер сделает

            pkt.accept()

        except Exception as e:
            logger.error(f"Palimpsest callback error: {e}")
            try:
                pkt.accept()
            except Exception:
                pass

    def _modify_syn_options(self, pkt):
        """Модифицировать TCP-опции SYN-пакета."""
        if not pkt.haslayer(TCP):
            return pkt

        tcp = pkt[TCP]
        # Меняем Window Scale (опция 3)
        new_options = []
        for opt in (tcp.options or []):
            if opt[0] == "WScale":
                # Случайный window scale
                new_options.append(("WScale", random.randint(5, 10)))
            elif opt[0] == "Timestamp":
                # Смещаем timestamp
                ts_val, ts_ecr = opt[1]
                offset = random.randint(-1000, 1000)
                new_options.append(("Timestamp", (ts_val + offset, ts_ecr)))
            elif opt[0] == "MSS":
                # Случайный MSS
                new_options.append(("MSS", random.choice([1360, 1400, 1420, 1460])))
            else:
                new_options.append(opt)

        tcp.options = new_options

        # Пересчёт чексумм
        del pkt[IP].chksum
        del tcp.chksum
        pkt = IP(raw(pkt))

        return pkt

    def start(self, target_ips: list, target_port: int):
        """Запустить перехват через NFQUEUE."""
        if not HAS_NFQUEUE:
            logger.error(
                "Метод 2 (Палимпсест): netfilterqueue не установлен. "
                "pip install netfilterqueue"
            )
            return False

        if not HAS_SCAPY:
            logger.error("Метод 2: scapy не установлен")
            return False

        # Добавляем iptables правила для каждого целевого IP
        for ip in target_ips:
            # Исходящие
            self.iptables.add_nfqueue_rule(
                ip, target_port, self.queue_num, "tcp", "OUTPUT"
            )
            # Входящие ответы
            self.iptables.add_input_nfqueue_rule(
                ip, target_port, self.queue_num, "tcp"
            )

        # Запускаем NFQUEUE
        self.nfq = NetfilterQueue()
        self.nfq.bind(self.queue_num, self._packet_callback)

        self.running = True
        self.thread = threading.Thread(
            target=self._run_queue, daemon=True, name="palimpsest-nfq"
        )
        self.thread.start()
        logger.info(f"Palimpsest: NFQUEUE {self.queue_num} запущен")
        return True

    def _run_queue(self):
        try:
            self.nfq.run()
        except Exception as e:
            if self.running:
                logger.error(f"Palimpsest NFQUEUE error: {e}")

    def stop(self):
        self.running = False
        if self.nfq:
            try:
                self.nfq.unbind()
            except Exception:
                pass
        logger.info("Palimpsest: остановлен")


# ──────────────────────────────────────────────
# Метод 3: Фрагментация IP
# ──────────────────────────────────────────────

class MethodFragment:
    """
    Метод «Фрагментация IP»:
    Перехватывает исходящие TCP-пакеты (SYN, ClientHello) через NFQUEUE
    и разбивает их на мелкие IP-фрагменты.

    DPI часто не собирает фрагменты перед анализом, поэтому
    не может распознать сигнатуры в разбитых пакетах.
    """

    def __init__(self, config: dict, iptables_mgr: IptablesManager):
        self.config = config
        self.fcfg = config["fragment"]
        self.iptables = iptables_mgr

        self.queue_num = self.fcfg["nfqueue_num"]
        self.frag_size = self.fcfg["frag_size"]
        self.target_phases = self.fcfg.get("target_phases", ["syn", "client_hello"])

        self.connections = defaultdict(lambda: {"packet_count": 0})
        self.lock = threading.Lock()
        self.running = False
        self.nfq = None
        self.thread = None

    def _is_client_hello(self, payload: bytes) -> bool:
        """Проверить, является ли TCP payload TLS ClientHello."""
        if len(payload) < 6:
            return False
        # TLS Record: ContentType=22 (Handshake), Version, Length
        # Handshake: Type=1 (ClientHello)
        return payload[0] == 0x16 and payload[5] == 0x01

    def _packet_callback(self, pkt):
        """Обработчик пакетов для фрагментации."""
        try:
            if not HAS_SCAPY:
                pkt.accept()
                return

            scapy_pkt = IP(pkt.get_payload())

            if not scapy_pkt.haslayer(TCP):
                pkt.accept()
                return

            tcp = scapy_pkt[TCP]
            conn_key = (scapy_pkt.src, tcp.sport, scapy_pkt.dst, tcp.dport)
            should_fragment = False

            with self.lock:
                conn = self.connections[conn_key]
                conn["packet_count"] += 1

            # Проверяем, нужно ли фрагментировать
            # SYN-пакет
            if "syn" in self.target_phases and (tcp.flags & 0x02) and not (tcp.flags & 0x10):
                should_fragment = True
                logger.debug(f"Fragment: SYN detected {conn_key}")

            # ClientHello
            if "client_hello" in self.target_phases and tcp.payload:
                payload_bytes = bytes(tcp.payload)
                if self._is_client_hello(payload_bytes):
                    should_fragment = True
                    logger.debug(f"Fragment: ClientHello detected {conn_key}")

            if should_fragment:
                self._fragment_and_send(scapy_pkt, pkt)
            else:
                pkt.accept()

        except Exception as e:
            logger.error(f"Fragment callback error: {e}")
            try:
                pkt.accept()
            except Exception:
                pass

    def _fragment_and_send(self, scapy_pkt, nfq_pkt):
        """Фрагментировать IP-пакет и отправить фрагменты."""
        try:
            # Фрагментируем с помощью scapy
            frags = fragment(scapy_pkt, fragsize=self.frag_size)

            if len(frags) <= 1:
                # Пакет слишком мал для фрагментации
                nfq_pkt.accept()
                return

            # Отправляем фрагменты напрямую
            for i, frag_pkt in enumerate(frags):
                # Добавляем случайную микрозадержку между фрагментами
                if i > 0:
                    time.sleep(random.uniform(0.001, 0.01))
                send(frag_pkt, verbose=0)

            logger.debug(
                f"Fragment: отправлено {len(frags)} фрагментов "
                f"(размер={self.frag_size}B)"
            )

            # Дропаем оригинальный пакет
            nfq_pkt.drop()

        except Exception as e:
            logger.error(f"Fragment send error: {e}")
            try:
                nfq_pkt.accept()
            except Exception:
                pass

    def start(self, target_ips: list, target_port: int):
        """Запустить перехват через NFQUEUE."""
        if not HAS_NFQUEUE:
            logger.error(
                "Метод 3 (Фрагментация): netfilterqueue не установлен. "
                "pip install netfilterqueue"
            )
            return False

        if not HAS_SCAPY:
            logger.error("Метод 3: scapy не установлен")
            return False

        for ip in target_ips:
            self.iptables.add_nfqueue_rule(
                ip, target_port, self.queue_num, "tcp", "OUTPUT"
            )

        self.nfq = NetfilterQueue()
        self.nfq.bind(self.queue_num, self._packet_callback)

        self.running = True
        self.thread = threading.Thread(
            target=self._run_queue, daemon=True, name="fragment-nfq"
        )
        self.thread.start()
        logger.info(f"Fragment: NFQUEUE {self.queue_num} запущен, frag_size={self.frag_size}B")
        return True

    def _run_queue(self):
        try:
            self.nfq.run()
        except Exception as e:
            if self.running:
                logger.error(f"Fragment NFQUEUE error: {e}")

    def stop(self):
        self.running = False
        if self.nfq:
            try:
                self.nfq.unbind()
            except Exception:
                pass
        logger.info("Fragment: остановлен")


class Socks5Server:
    """Исправленный SOCKS5 прокси-сервер"""

    def __init__(self, config: dict, evader_ref):
        scfg = config["socks5"]
        self.listen_host = scfg["listen_host"]
        self.listen_port = scfg["listen_port"]
        self.evader = evader_ref
        self.running = False
        self.server_sock = None
        self.thread = None

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.listen_host, self.listen_port))
        self.server_sock.listen(50)
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        logger.info(f"SOCKS5: слушаю {self.listen_host}:{self.listen_port}")

    def _accept_loop(self):
        while self.running:
            try:
                client, addr = self.server_sock.accept()
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except OSError:
                break

    def _handle_client(self, client):
        try:
            # Handshake
            data = self._recv_exact(client, 2)
            if len(data) < 2 or data[0] != 5:
                client.close()
                return
            nmethods = data[1]
            if nmethods:
                self._recv_exact(client, nmethods)
            client.send(b'\x05\x00')

            # Request
            data = self._recv_exact(client, 4)
            if len(data) < 4 or data[0] != 5 or data[1] != 1:
                client.close()
                return
            atyp = data[3]
            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(self._recv_exact(client, 4))
            elif atyp == 3:  # Domain name
                dlen = self._recv_exact(client, 1)[0]
                addr = self._recv_exact(client, dlen).decode()
            elif atyp == 4:  # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, self._recv_exact(client, 16))
            else:
                client.close()
                return
            port = struct.unpack('!H', self._recv_exact(client, 2))[0]

            logger.info(f"SOCKS5: CONNECT {addr}:{port} (ATYP=0x{atyp:02x})")

            # Connect via MethodParadox
            morse = self.evader.paradox.connect(addr, port)
            remote_sock = morse.sock
            bind_addr = remote_sock.getsockname()
            bind_ip = socket.inet_aton(bind_addr[0])
            bind_port = struct.pack('!H', bind_addr[1])
            client.send(b'\x05\x00\x00\x01' + bind_ip + bind_port)

            # Bridge
            self._bridge(client, remote_sock)
        except Exception as e:
            logger.error(f"SOCKS5 handler error: {e}")
            try:
                client.send(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                client.close()
            except:
                pass

    def _recv_exact(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("socket closed")
            data += chunk
        return data

    def _bridge(self, client, remote):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    client.close()
                except:
                    pass
                try:
                    remote.close()
                except:
                    pass
        t1 = threading.Thread(target=forward, args=(client, remote), daemon=True)
        t2 = threading.Thread(target=forward, args=(remote, client), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()
        logger.info("SOCKS5: остановлен")


# ──────────────────────────────────────────────
# DPIEvader — главный оркестратор
# ──────────────────────────────────────────────

class DPIEvader:
    """
    Главный класс, управляющий всеми методами обхода DPI.

    Пример:
        evader = DPIEvader("config.yaml")
        evader.run()
    """

    def __init__(self, config_path=None):
        self.config = load_config(config_path)
        self.iptables = IptablesManager(
            auto_manage=self.config["iptables"]["auto_manage"],
            cleanup_on_exit=self.config["iptables"]["cleanup_on_exit"],
        )

        self.paradox = MethodParadox(self.config)
        self.palimpsest = MethodPalimpsest(self.config, self.iptables)
        self.fragment = MethodFragment(self.config, self.iptables)
        self.distractor = None
        self.decoy_tunnel = DecoyTunnel(self.config)
        self.socks5 = Socks5Server(self.config, self)

        self.active_connections = []  # MorseSender'ы
        self.ip_cache = {}

    def _resolve(self, domain: str) -> str:
        if domain in self.ip_cache:
            return self.ip_cache[domain]
        try:
            ip = socket.gethostbyname(domain)
            self.ip_cache[domain] = ip
            return ip
        except socket.gaierror as e:
            logger.error(f"DNS resolve failed for {domain}: {e}")
            return None

    def _resolve_all_targets(self) -> list:
        """Резолвить все целевые домены в IP-адреса."""
        ips = list(self.config.get("target_ips", []))
        for domain in self.config["target_domains"]:
            ip = self._resolve(domain)
            if ip and ip not in ips:
                ips.append(ip)
        return ips

    def _method_paradox(self, domain: str, port: int):
        """Метод 1 — Парадокс."""
        print(f"\n  [Метод 1 — Парадокс] {domain}:{port}")
        try:
            morse = self.paradox.connect(domain, port)
            self.active_connections.append(morse)
            print(f"    ✓ Соединение установлено через MorseSender")
            mcfg = self.config["morse"]
            print(f"    ✓ Chunk: {mcfg['min_chunk_size']}-{mcfg['max_chunk_size']}B, "
                  f"пауза: {mcfg['min_pause']}-{mcfg['max_pause']}s (Пуассон λ={mcfg['poisson_lambda']})")
            return morse
        except Exception as e:
            print(f"    ✗ Ошибка: {e}")
            return None

    def _method_delay(self, target_ips: list, port: int):
        """Метод 2 — Палимпсест через NFQUEUE."""
        print(f"\n  [Метод 2 — Палимпсест (задержка)]")
        if not HAS_NFQUEUE:
            print("    ⚠ netfilterqueue не установлен")
            print("    ⚠ pip install netfilterqueue")
            return False
        if not HAS_SCAPY:
            print("    ⚠ scapy не установлен")
            return False

        success = self.palimpsest.start(target_ips, port)
        if success:
            pcfg = self.config["palimpsest"]
            print(f"    ✓ NFQUEUE {pcfg['nfqueue_num']} активен")
            print(f"    ✓ Задержка: {pcfg['delay_ms']}ms, "
                  f"макс пакетов: {pcfg['max_delayed_packets']}")
            print(f"    ✓ Модификация SYN: {'вкл' if pcfg['modify_syn_options'] else 'выкл'}")
        else:
            print(f"    ✗ Не удалось запустить")
        return success

    def _method_fragment(self, target_ips: list, port: int):
        """Метод 3 — Фрагментация IP через NFQUEUE."""
        print(f"\n  [Метод 3 — Фрагментация IP]")
        if not HAS_NFQUEUE:
            print("    ⚠ netfilterqueue не установлен")
            print("    ⚠ pip install netfilterqueue")
            return False
        if not HAS_SCAPY:
            print("    ⚠ scapy не установлен")
            return False

        success = self.fragment.start(target_ips, port)
        if success:
            fcfg = self.config["fragment"]
            print(f"    ✓ NFQUEUE {fcfg['nfqueue_num']} активен")
            print(f"    ✓ Размер фрагмента: {fcfg['frag_size']}B")
            print(f"    ✓ Целевые фазы: {fcfg['target_phases']}")
        else:
            print(f"    ✗ Не удалось запустить")
        return success

    def start_distractor(self):
        """Запустить отвлекающий трафик."""
        if self.config["distractor"]["enabled"] and self.distractor is None:
            self.distractor = RussianDistractor(self.config)
            dcfg = self.config["distractor"]
            print(f"\n  [Отвлекающий трафик]")
            print(f"    ✓ HTTP: {len(dcfg['sites'])} сайтов")
            print(f"    ✓ ICMP: {'вкл' if dcfg.get('icmp_enabled') else 'выкл'}")
            print(f"    ✓ TCP half-open: {'вкл' if dcfg.get('tcp_halfopen_enabled') else 'выкл'}")
            print(f"    ✓ DoH noise: {'вкл' if dcfg.get('doh_noise_enabled') else 'выкл'}")
            print(f"    ✓ Адаптивная интенсивность: {'вкл' if dcfg.get('adaptive_intensity') else 'выкл'}")

    def start_decoy_tunnel(self):
        """Запустить жертвенный туннель-приманку."""
        if self.decoy_tunnel.start():
            print(f"\n  [Жертвенный туннель]")
            dcfg = self.config["decoy_tunnel"]
            print(f"    ✓ {dcfg['type']} -> {dcfg['server']}:{dcfg['port']}")
            print(f"    ✓ Health-check каждые {dcfg['health_check_interval']}с")
            print(f"    ✓ Auto-restart: {'вкл' if dcfg['auto_restart'] else 'выкл'}")

            # Перенаправляем distractor через туннель
            if self.distractor:
                self.decoy_tunnel.route_distractor_through_tunnel(self.distractor)
                print(f"    ✓ Отвлекающий трафик направлен через туннель")
        else:
            print(f"\n  [Жертвенный туннель] ✗ Не удалось запустить")

    def start_socks5(self):
        """Запустить SOCKS5 прокси."""
        if self.config["socks5"]["enabled"]:
            self.socks5.start()
            scfg = self.config["socks5"]
            print(f"\n  [SOCKS5 прокси]")
            print(f"    ✓ {scfg['listen_host']}:{scfg['listen_port']}")
            print(f"    ✓ Используйте: socks5://{scfg['listen_host']}:{scfg['listen_port']}")

    def run_for_domain(self, domain: str, port: int = 443):
        """Запустить все методы для одного домена."""
        print(f"\n{'='*60}")
        print(f"  Цель: {domain}:{port}")
        print(f"{'='*60}")

        ip = self._resolve(domain)
        if not ip:
            print(f"  ✗ Не удалось резолвить {domain}")
            return {}

        print(f"  IP: {ip}")
        methods = self.config["methods"]
        results = {}

        if 1 in methods:
            results[1] = self._method_paradox(domain, port)

        if 2 in methods:
            results[2] = self._method_delay([ip], port)

        if 3 in methods:
            results[3] = self._method_fragment([ip], port)

        self.start_distractor()
        return results

    def run(self):
        """Запустить обход для всех доменов из конфига."""
        domains = self.config["target_domains"]
        port = self.config.get("target_port", 443)

        print(f"\n{'═'*60}")
        print(f"  DPI Evader v3 — Многоуровневый обход")
        print(f"{'═'*60}")
        print(f"  Методы: {self.config['methods']}")
        print(f"  Цели: {len(domains)} доменов")
        print(f"  Порт: {port}")
        print(f"  Morse: {'вкл' if self.config['morse']['enabled'] else 'выкл'}")
        print(f"  Distractor: {'вкл' if self.config['distractor']['enabled'] else 'выкл'}")

        # Проверка зависимостей
        print(f"\n  Зависимости:")
        print(f"    scapy: {'✓' if HAS_SCAPY else '✗ (методы 2,3 и ICMP недоступны)'}")
        print(f"    netfilterqueue: {'✓' if HAS_NFQUEUE else '✗ (методы 2,3 недоступны)'}")
        print(f"    requests: {'✓' if HAS_REQUESTS else '✗ (HTTP distractor недоступен)'}")

        # Проверка root
        is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        print(f"    root: {'✓' if is_root else '⚠ (raw sockets, iptables могут не работать)'}")

        # Резолвим все цели
        all_ips = self._resolve_all_targets()
        if not all_ips:
            print("\n  ✗ Ни один домен не резолвился. Проверьте DNS.")
            return

        methods = self.config["methods"]

        # Методы 2 и 3 — запускаем один раз для всех IP
        if 2 in methods:
            self._method_delay(all_ips, port)

        if 3 in methods:
            self._method_fragment(all_ips, port)

        # Метод 1 — для каждого домена
        if 1 in methods:
            for domain in domains:
                self._method_paradox(domain, port)

        # Отвлекающий трафик
        self.start_distractor()

        # Жертвенный туннель (после distractor — чтобы перенаправить его)
        if self.config["decoy_tunnel"]["enabled"]:
            self.start_decoy_tunnel()

        # SOCKS5 прокси — точка входа для приложений
        self.start_socks5()

        print(f"\n{'═'*60}")
        print(f"  Все методы запущены. Нажмите Ctrl+C для остановки.")
        print(f"{'═'*60}")

        # Основной цикл с периодической статистикой
        try:
            stats_interval = 60  # Выводить статистику каждые 60 секунд
            counter = 0
            while True:
                time.sleep(1)
                counter += 1
                if counter % stats_interval == 0:
                    self._print_stats()
        except KeyboardInterrupt:
            print("\n\n  Остановка...")
            self._shutdown()

    def _print_stats(self):
        """Вывести текущую статистику."""
        print(f"\n  ─── Статистика ({datetime.now().strftime('%H:%M:%S')}) ───")

        for i, morse in enumerate(self.active_connections):
            stats = morse.get_stats()
            print(f"    Conn #{i}: {stats['bytes_sent']}B отправлено, "
                  f"{stats['chunks_sent']} чанков, "
                  f"{stats['keepalives']} keep-alive")

        if self.distractor:
            dstats = self.distractor.get_stats()
            print(f"    Distractor: HTTP={dstats.get('http_requests', 0)}, "
                  f"ICMP={dstats.get('icmp_sent', 0)}, "
                  f"TCP={dstats.get('tcp_halfopen_opened', 0)}, "
                  f"DoH={dstats.get('doh_queries', 0)}")

        if self.distractor and self.distractor.intensity:
            mult = self.distractor.intensity.get_multiplier()
            print(f"    Интенсивность: x{mult:.1f}")

    def _shutdown(self):
        """Корректная остановка всех компонентов."""
        # Остановить MorseSender'ы
        for morse in self.active_connections:
            try:
                morse.close()
            except Exception:
                pass

        # Остановить NFQUEUE
        self.palimpsest.stop()
        self.fragment.stop()

        # Остановить distractor
        if self.distractor:
            self.distractor.stop()

        # Остановить жертвенный туннель
        self.decoy_tunnel.stop()

        # Остановить SOCKS5
        self.socks5.stop()

        # iptables cleanup (также через atexit)
        self.iptables.cleanup()

        print("  Всё остановлено.")

    # ──────────────────────────────────────────────
    # Auto-Tune — автоматическая настройка параметров
    # ──────────────────────────────────────────────

    def auto_tune(self, target_domain=None, max_tests=20):
        """
        Автоматический подбор оптимальных параметров обхода DPI.

        Перебирает комбинации параметров morse (chunk, pause, lambda),
        methods, palimpsest и fragment, тестирует соединение к test_domain,
        замеряет время ответа и выбирает лучшую комбинацию.

        Аргументы:
            target_domain: домен для тестирования (по умолчанию yandex.ru)
            max_tests: максимальное число комбинаций для перебора

        Возвращает:
            dict с лучшими параметрами, или None при ошибке
        """
        import copy
        import itertools
        import random as rnd

        print(f"\n{'═'*60}")
        print(f"  Автоматическая настройка параметров (auto-tune)")
        print(f"{'═'*60}")

        domain = target_domain or self.config.get("auto_tune", {}).get("test_domain", "yandex.ru")
        port = self.config.get("target_port", 443)
        print(f"  Целевой домен: {domain}:{port}")

        # Сохраняем исходную конфигурацию
        saved_config = copy.deepcopy(self.config)
        restored = False

        def restore_config():
            nonlocal restored
            if not restored:
                self.config = saved_config
                restored = True

        # Обработка Ctrl+C
        import signal
        def signal_handler(sig, frame):
            print("\n\n  Прерывание! Восстанавливаю конфиг...")
            restore_config()
            self._shutdown()
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)

        # Отключаем distractor на время тестов
        distractor_was_enabled = self.config["distractor"]["enabled"]
        self.config["distractor"]["enabled"] = False
        if self.distractor:
            self.distractor.stop()
            self.distractor = None

        # Останавливаем активные соединения MorseSender (без iptables/NFQUEUE)
        for morse in self.active_connections:
            try:
                morse.close()
            except Exception:
                pass
        self.active_connections.clear()

        import shutil

        # Проверка доступности методов
        available_methods = [1]
        if HAS_NFQUEUE and HAS_SCAPY and shutil.which("iptables"):
            available_methods.append(2)
            available_methods.append(3)

        # Генерация пространства параметров
        chunk_candidates = [64, 128, 256, 512]
        pause_candidates = [0.5, 2.0, 5.0, 10.0]
        lambda_candidates = [2.0, 5.0, 10.0]
        delay_candidates = [20, 50, 100]
        max_delayed_candidates = [5, 10, 20]
        frag_candidates = [4, 8, 16]
        method_combos = [[1]]
        if 2 in available_methods:
            method_combos.append([1, 2])
        if 3 in available_methods:
            method_combos.append([1, 3])
        if 2 in available_methods and 3 in available_methods:
            method_combos.append([1, 2, 3])

        # Строим все комбинации
        all_combos = []
        for chunk, pause, lam, methods in itertools.product(
            chunk_candidates, pause_candidates, lambda_candidates, method_combos
        ):
            combo = {
                "morse": {
                    "min_chunk_size": chunk,
                    "max_chunk_size": min(chunk * 2, 1024),
                    "min_pause": pause,
                    "max_pause": min(pause * 3, 30.0),
                    "poisson_lambda": lam,
                },
                "methods": methods,
            }
            # Добавляем palimpsest параметры если active method 2
            if 2 in methods:
                for delay, md in itertools.product(delay_candidates, max_delayed_candidates):
                    c = copy.deepcopy(combo)
                    c["palimpsest"] = {"delay_ms": delay, "max_delayed_packets": md}
                    all_combos.append(c)
            else:
                all_combos.append(combo)

            # Добавляем fragment параметры если active method 3
            if 3 in methods and 2 not in methods:
                for frag in frag_candidates:
                    c = copy.deepcopy(combo)
                    c["fragment"] = {"frag_size": frag}
                    all_combos.append(c)

        # Если комбинаций больше max_tests — случайная выборка
        total = len(all_combos)
        if total > max_tests:
            all_combos = rnd.sample(all_combos, max_tests)
            print(f"  Всего комбинаций: {total}, тестируется: {max_tests} (случайная выборка)")
        else:
            print(f"  Всего комбинаций: {total}")

        print()

        results = []
        for idx, combo in enumerate(all_combos, 1):
            # Применяем параметры
            for section, params in combo.items():
                if section in self.config:
                    self.config[section].update(params)
                else:
                    self.config[section] = params

            # Формируем краткое описание
            m = combo["morse"]
            desc = (f"chunks={m['min_chunk_size']:.0f}..{m['max_chunk_size']:.0f}, "
                    f"pause={m['min_pause']:.1f}..{m['max_pause']:.1f}s, "
                    f"λ={m['poisson_lambda']:.1f}, methods={combo['methods']}")

            print(f"  [{idx}/{total}] Тестирование: {desc} ... ", end="", flush=True)

            # Тест соединения через реальный метод 1 (Paradox)
            connect_time = None
            response_time = None
            success = False
            try:
                t0 = time.perf_counter()

                # Создаём временный MethodParadox с этими параметрами
                test_paradox = MethodParadox(self.config)
                test_morse = test_paradox.connect(domain, port)
                connect_time = time.perf_counter() - t0

                # Отправляем HTTP GET через MorseSender
                http_req = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
                test_morse.send(http_req)

                # Ждём первый байт ответа (читаем из сырого сокета)
                test_morse.sock.settimeout(10)
                t1 = time.perf_counter()
                data = test_morse.sock.recv(1)
                response_time = time.perf_counter() - t1

                if data:
                    success = True

                test_morse.close()
            except Exception as e:
                response_time = None
                connect_time = connect_time or 999.0

            # Сохраняем результат
            results.append({
                "combo": combo,
                "desc": desc,
                "success": success,
                "connect_time": connect_time,
                "response_time": response_time,
            })

            if success:
                print(f"OK (ответ за {response_time:.2f}s)")
            else:
                print(f"FAIL (таймаут/ошибка)")

            # Восстанавливаем базовые настройки для следующей итерации
            self.config["morse"] = saved_config["morse"].copy()
            self.config["methods"] = saved_config["methods"].copy()

        # Восстанавливаем конфиг
        restore_config()

        # Анализ результатов
        successful = [r for r in results if r["success"]]
        if successful:
            best = min(successful, key=lambda r: r["response_time"] or 999)
        elif results:
            best = min(results, key=lambda r: r["connect_time"] or 999)
            if not best.get("success"):
                best["warning"] = True
        else:
            print("\n  ✗ Нет завершённых тестов.")
            self.config["distractor"]["enabled"] = distractor_was_enabled
            return None

        # Вывод таблицы лучших
        print(f"\n  Лучшие комбинации:")
        sorted_results = sorted(
            [r for r in results if r["success"] or True],
            key=lambda r: (r["response_time"] or 999, r["connect_time"] or 999)
        )[:5]

        for rank, r in enumerate(sorted_results, 1):
            tm = r["response_time"] if r["success"] else r["connect_time"]
            tag = "ответ" if r["success"] else "connect"
            warn = " ⚠ (нет успешных)" if r.get("warning") else ""
            print(f"    {rank}. время={tm:.2f}s ({tag}), params: {r['desc']}{warn}")

        # Предложение сохранить
        print()
        try:
            answer = input("  Сохранить лучшую комбинацию в config.yaml? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        if answer in ("y", "yes", "д", "да"):
            self.config = saved_config.copy()
            # Применяем лучшие параметры поверх
            for section, params in best["combo"].items():
                if section in self.config:
                    self.config[section].update(params)
                else:
                    self.config[section] = params

            # Сохраняем
            save_path = DEFAULT_CONFIG_PATH
            with open(save_path, "w") as f:
                yaml.dump(dict(self.config), f, default_flow_style=False, allow_unicode=True)
            print(f"  ✓ Конфиг сохранён: {save_path}")
        else:
            print("  Конфиг не изменён.")

        # Восстанавливаем distractor
        self.config["distractor"]["enabled"] = distractor_was_enabled

        print(f"\n  Автонастройка завершена.")
        return best["combo"]


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DPI Evader v3 — Многоуровневый обход DPI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Сгенерировать конфиг
  sudo python3 dpi_evader.py --init-config

  # Запустить со всеми методами
  sudo python3 dpi_evader.py

  # Запустить для одного домена
  sudo python3 dpi_evader.py -d youtube.com

  # Только метод 1 (без root для NFQUEUE)
  sudo python3 dpi_evader.py -d example.com --methods 1
        """
    )
    parser.add_argument(
        "-c", "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Путь к config.yaml"
    )
    parser.add_argument(
        "--init-config",
        action="store_true",
        help="Сгенерировать config.yaml и выйти"
    )
    parser.add_argument(
        "-d", "--domain",
        help="Один домен (вместо списка из config)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Порт цели (по умолчанию 443)"
    )
    parser.add_argument(
        "--methods",
        type=str,
        default=None,
        help="Методы через запятую, например: 1,2,3"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод (DEBUG)"
    )
    parser.add_argument(
        "--no-distractor",
        action="store_true",
        help="Отключить отвлекающий трафик"
    )
    parser.add_argument(
        "--auto-tune",
        action="store_true",
        help="Режим автоматической настройки параметров"
    )
    parser.add_argument(
        "--max-tests",
        type=int,
        default=20,
        help="Максимум комбинаций для auto-tune (по умолчанию 20)"
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "wsl", "linux"],
        default="auto",
        help="Режим работы: auto (определение WSL), wsl (только метод1), linux (полный)"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.init_config:
        save_default_config(args.config)
        return

    # Проверка root-прав
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("⚠ Требуются root-права для raw sockets, iptables, NFQUEUE.")
        print("  Запустите с sudo.")
        if not args.domain or args.methods == "1":
            # Метод 1 (Paradox) использует raw sockets — тоже root
            print("  Метод 1 (Paradox) тоже требует root из-за raw sockets.")
        sys.exit(1)

    evader = DPIEvader(args.config)

    # Применяем настройки режима
    if args.mode == "wsl":
        evader.config["methods"] = [1]
        evader.config["iptables"]["auto_manage"] = False
        evader.config["decoy_tunnel"]["enabled"] = False
        if "distractor" in evader.config:
            evader.config["distractor"]["enabled"] = False
        print("Режим WSL: методы 2/3, iptables, DecoyTunnel, Distractor отключены")
    elif args.mode == "linux":
        # Оставляем как есть (используем config.yaml)
        print("Режим Linux: полный функционал")
    else:  # auto
        # Попытка определить WSL по наличию файла /proc/sys/fs/binfmt_misc/WSLInterop
        if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
            print("Auto: обнаружен WSL, переключаюсь в режим wsl")
            evader.config["methods"] = [1]
            evader.config["iptables"]["auto_manage"] = False
            evader.config["decoy_tunnel"]["enabled"] = False
            evader.config["distractor"]["enabled"] = False
        else:
            print("Auto: полноценный Linux, оставляю полный функционал")

    # Переопределения из CLI
    if args.methods:
        evader.config["methods"] = [int(m) for m in args.methods.split(",")]

    if args.no_distractor:
        evader.config["distractor"]["enabled"] = False

    if args.auto_tune:
        evader.auto_tune(target_domain=args.domain, max_tests=args.max_tests)
        return

    if args.domain:
        evader.run_for_domain(args.domain, args.port)
        # Держим процесс живым
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nОстановка...")
            evader._shutdown()
    else:
        evader.run()


if __name__ == "__main__":
    main()