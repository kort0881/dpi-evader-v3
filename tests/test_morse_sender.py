"""
Тесты для MorseSender.
"""

import io
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock


# Добавляем родительскую директорию в путь
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dpi_evader import MorseSender


class FakeSocket:
    """Мок сокета для тестов."""

    def __init__(self):
        self.sent_data = bytearray()
        self.lock = threading.Lock()
        self.closed = False
        self.send_error = None

    def sendall(self, data):
        if self.send_error:
            raise self.send_error
        with self.lock:
            self.sent_data.extend(data)

    def close(self):
        self.closed = True

    def get_sent(self) -> bytes:
        with self.lock:
            return bytes(self.sent_data)


class TestMorseSender(unittest.TestCase):

    def test_basic_send(self):
        """Данные должны быть отправлены через сокет."""
        sock = FakeSocket()
        morse = MorseSender(
            sock,
            min_chunk_size=10, max_chunk_size=10,
            min_pause=0.01, max_pause=0.02,
            keepalive_enabled=False,
            poisson_lambda=0.01,
        )

        test_data = b"Hello, World!!"  # 14 байт
        morse.send(test_data)

        # Ждём отправки (минимум 2 итерации для 14 байт при chunk=10)
        time.sleep(0.5)

        sent = sock.get_sent()
        # Должно быть отправлено хотя бы частично
        self.assertGreater(len(sent), 0)
        # Все отправленные данные — подмножество исходных
        self.assertTrue(test_data.startswith(sent) or sent in test_data + b"\x00")

        morse.close()

    def test_flush(self):
        """flush() должен отправить все оставшиеся данные."""
        sock = FakeSocket()
        morse = MorseSender(
            sock,
            min_chunk_size=1000, max_chunk_size=1000,  # Большой чанк
            min_pause=10, max_pause=20,  # Большая пауза
            keepalive_enabled=False,
            poisson_lambda=15.0,
        )

        test_data = b"Short data"
        morse.send(test_data)
        time.sleep(0.1)  # Данные в буфере, но не отправлены (чанк > данных)

        morse.flush()
        time.sleep(0.1)

        sent = sock.get_sent()
        self.assertIn(test_data, sent)
        self.assertTrue(sock.closed)

    def test_close(self):
        """close() должен закрыть сокет."""
        sock = FakeSocket()
        morse = MorseSender(
            sock,
            min_chunk_size=64, max_chunk_size=64,
            min_pause=0.01, max_pause=0.02,
            keepalive_enabled=False,
        )
        morse.close()
        time.sleep(0.1)
        self.assertTrue(sock.closed)
        self.assertFalse(morse.running)

    def test_stats(self):
        """Статистика должна обновляться."""
        sock = FakeSocket()
        morse = MorseSender(
            sock,
            min_chunk_size=5, max_chunk_size=5,
            min_pause=0.01, max_pause=0.02,
            keepalive_enabled=False,
            poisson_lambda=0.01,
        )

        morse.send(b"0123456789")  # 10 байт, 2 чанка по 5
        time.sleep(1)

        stats = morse.get_stats()
        self.assertGreaterEqual(stats["chunks_sent"], 1)
        self.assertGreaterEqual(stats["bytes_sent"], 5)

        morse.close()

    def test_send_error_stops_loop(self):
        """При ошибке отправки цикл должен остановиться."""
        sock = FakeSocket()
        sock.send_error = ConnectionError("broken pipe")

        morse = MorseSender(
            sock,
            min_chunk_size=5, max_chunk_size=5,
            min_pause=0.01, max_pause=0.02,
            keepalive_enabled=False,
            poisson_lambda=0.01,
        )

        morse.send(b"0123456789")
        time.sleep(0.5)

        self.assertFalse(morse.running)
        morse.close()

    def test_keepalive(self):
        """Keep-alive должен отправлять пустой TLS record."""
        sock = FakeSocket()
        morse = MorseSender(
            sock,
            min_chunk_size=1000, max_chunk_size=1000,
            min_pause=100, max_pause=200,
            keepalive_enabled=True,
            keepalive_interval=0.5,  # Короткий интервал для теста
        )

        time.sleep(1.5)  # Ждём 2+ keep-alive

        stats = morse.get_stats()
        self.assertGreaterEqual(stats["keepalives"], 1)

        sent = sock.get_sent()
        self.assertIn(b"\x17\x03\x03", sent)  # TLS Application Data record

        morse.close()


class TestMorseSenderPoissonPause(unittest.TestCase):

    def test_poisson_pause_range(self):
        """Паузы должны быть в пределах min_pause..max_pause."""
        sock = FakeSocket()
        morse = MorseSender(
            sock,
            min_chunk_size=64, max_chunk_size=64,
            min_pause=1.0, max_pause=10.0,
            keepalive_enabled=False,
            poisson_lambda=3.0,
        )

        for _ in range(100):
            pause = morse._poisson_pause()
            self.assertGreaterEqual(pause, 1.0)
            self.assertLessEqual(pause, 10.0)

        morse.close()

    def test_random_chunk_size(self):
        """Размер чанка должен быть случайным в заданном диапазоне."""
        sock = FakeSocket()
        morse = MorseSender(
            sock,
            min_chunk_size=64, max_chunk_size=512,
            min_pause=0.01, max_pause=0.02,
            keepalive_enabled=False,
        )

        sizes = set()
        for _ in range(100):
            size = morse._random_chunk_size()
            self.assertGreaterEqual(size, 64)
            self.assertLessEqual(size, 512)
            sizes.add(size)

        # Должно быть хотя бы несколько разных размеров
        self.assertGreater(len(sizes), 5)

        morse.close()


if __name__ == "__main__":
    unittest.main()
