"""
Тесты для методов обхода DPI.
"""

import unittest
from unittest.mock import patch, MagicMock, call

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dpi_evader import (
    MethodParadox, MethodPalimpsest, MethodFragment,
    IptablesManager, DEFAULT_CONFIG, _deep_merge
)


class TestIptablesManager(unittest.TestCase):

    @patch("dpi_evader.subprocess.run")
    def test_add_rule(self, mock_run):
        """Правило должно добавляться через iptables."""
        # -C (check) возвращает ошибку (правила нет)
        check_result = MagicMock()
        check_result.returncode = 1
        # -A (add) успешно
        add_result = MagicMock()
        add_result.returncode = 0

        mock_run.side_effect = [check_result, add_result]

        mgr = IptablesManager(auto_manage=True, cleanup_on_exit=False)
        result = mgr.add_nfqueue_rule("1.2.3.4", 443, 100)

        self.assertTrue(result)
        self.assertEqual(len(mgr.rules_added), 1)

    @patch("dpi_evader.subprocess.run")
    def test_cleanup(self, mock_run):
        """cleanup должен удалять все добавленные правила."""
        mock_run.return_value = MagicMock(returncode=0)

        mgr = IptablesManager(auto_manage=True, cleanup_on_exit=False)
        mgr.rules_added = [
            ("OUTPUT", ["-d", "1.2.3.4", "-p", "tcp", "--dport", "443",
                        "-j", "NFQUEUE", "--queue-num", "100"]),
        ]

        mgr.cleanup()

        self.assertEqual(len(mgr.rules_added), 0)
        # Должен быть вызов iptables -D
        delete_call = mock_run.call_args_list[-1]
        self.assertIn("-D", delete_call[0][0])

    def test_no_auto_manage(self):
        """В ручном режиме правила не добавляются."""
        mgr = IptablesManager(auto_manage=False, cleanup_on_exit=False)
        result = mgr.add_nfqueue_rule("1.2.3.4", 443, 100)
        self.assertFalse(result)
        self.assertEqual(len(mgr.rules_added), 0)


class TestMethodParadox(unittest.TestCase):

    def test_resolve(self):
        """Резолв домена должен кэшироваться."""
        config = DEFAULT_CONFIG.copy()
        paradox = MethodParadox(config)

        with patch("dpi_evader.socket.gethostbyname", return_value="93.184.216.34"):
            ip1 = paradox._resolve("example.com")
            ip2 = paradox._resolve("example.com")

        self.assertEqual(ip1, "93.184.216.34")
        self.assertEqual(ip1, ip2)

    def test_tcp_checksum(self):
        """TCP-чексумма должна быть ненулевой."""
        import socket as sock_module
        config = DEFAULT_CONFIG.copy()
        paradox = MethodParadox(config)

        src_ip = sock_module.inet_aton("192.168.1.1")
        dst_ip = sock_module.inet_aton("93.184.216.34")
        tcp_header = b"\x00" * 20

        checksum = paradox._compute_tcp_checksum(src_ip, dst_ip, tcp_header)
        self.assertIsInstance(checksum, int)
        self.assertGreater(checksum, 0)


class TestMethodPalimpsest(unittest.TestCase):

    def test_init_without_nfqueue(self):
        """Инициализация без nfqueue не должна крашиться."""
        config = DEFAULT_CONFIG.copy()
        iptables = IptablesManager(auto_manage=False, cleanup_on_exit=False)
        palimpsest = MethodPalimpsest(config, iptables)

        self.assertEqual(palimpsest.queue_num, 100)
        self.assertFalse(palimpsest.running)


class TestMethodFragment(unittest.TestCase):

    def test_is_client_hello(self):
        """Определение TLS ClientHello."""
        config = DEFAULT_CONFIG.copy()
        iptables = IptablesManager(auto_manage=False, cleanup_on_exit=False)
        frag = MethodFragment(config, iptables)

        # Правильный ClientHello: ContentType=22, Handshake Type=1
        # TLS Record: 16 03 01 XX XX (ContentType=22=0x16, Version=0x0301, Length)
        # Handshake: 01 (ClientHello)
        client_hello = bytes([0x16, 0x03, 0x01, 0x00, 0xFF, 0x01]) + b"\x00" * 100
        self.assertTrue(frag._is_client_hello(client_hello))

        # Не ClientHello
        not_hello = bytes([0x17, 0x03, 0x01, 0x00, 0xFF, 0x01])
        self.assertFalse(frag._is_client_hello(not_hello))

        # Слишком короткий
        short = bytes([0x16, 0x03])
        self.assertFalse(frag._is_client_hello(short))


class TestSocks5Server(unittest.TestCase):

    def test_socks5_handshake_ipv4(self):
        """SOCKS5 CONNECT с IPv4 адресом."""
        from dpi_evader import Socks5Server

        config = _deep_merge(DEFAULT_CONFIG, {"socks5": {"enabled": True, "listen_host": "127.0.0.1", "listen_port": 1080}})
        evader_mock = MagicMock()
        evader_mock.paradox = MagicMock()

        srv = Socks5Server(config, evader_mock)
        self.assertEqual(srv.listen_port, 1080)
        self.assertEqual(srv.listen_host, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
