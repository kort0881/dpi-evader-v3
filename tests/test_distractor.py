"""
Тесты для RussianDistractor.
"""

import time
import unittest
from unittest.mock import patch, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dpi_evader import (
    RussianDistractor, IntensityController, DEFAULT_CONFIG, _deep_merge
)


class TestIntensityController(unittest.TestCase):

    def setUp(self):
        self.schedule = {
            "night": {"hours": [0,1,2,3,4,5,6], "multiplier": 0.3},
            "morning": {"hours": [7,8,9,10,11], "multiplier": 0.7},
            "day": {"hours": [12,13,14,15,16,17], "multiplier": 1.0},
            "evening": {"hours": [18,19,20,21,22,23], "multiplier": 1.5},
        }
        self.controller = IntensityController(self.schedule)

    def test_hour_map_complete(self):
        """Все 24 часа должны иметь множитель."""
        for h in range(24):
            self.assertIn(h, self.controller.hour_multiplier)

    def test_night_multiplier(self):
        """Ночные часы должны иметь множитель 0.3."""
        for h in [0, 1, 2, 3, 4, 5, 6]:
            self.assertAlmostEqual(self.controller.hour_multiplier[h], 0.3)

    def test_evening_multiplier(self):
        """Вечерние часы должны иметь множитель 1.5."""
        for h in [18, 19, 20, 21, 22, 23]:
            self.assertAlmostEqual(self.controller.hour_multiplier[h], 1.5)

    def test_adjust_pause_high_intensity(self):
        """При высокой интенсивности паузы должны быть короче."""
        # Мокаем get_multiplier чтобы вернуть 1.5
        self.controller.get_multiplier = lambda: 1.5

        adj_min, adj_max = self.controller.adjust_pause(10, 100)
        self.assertAlmostEqual(adj_min, 10 / 1.5)
        self.assertAlmostEqual(adj_max, 100 / 1.5)

    def test_adjust_pause_low_intensity(self):
        """При низкой интенсивности паузы должны быть длиннее."""
        self.controller.get_multiplier = lambda: 0.3

        adj_min, adj_max = self.controller.adjust_pause(10, 100)
        self.assertAlmostEqual(adj_min, 10 / 0.3)
        self.assertAlmostEqual(adj_max, 100 / 0.3)


class TestRussianDistractor(unittest.TestCase):

    @patch("dpi_evader.HAS_REQUESTS", True)
    @patch("dpi_evader.HAS_SCAPY", False)
    @patch("dpi_evader.requests")
    def test_distractor_starts_and_stops(self, mock_requests):
        """Distractor должен стартовать и останавливаться."""
        config = _deep_merge(DEFAULT_CONFIG, {
            "distractor": {
                "min_pause": 0.1,
                "max_pause": 0.2,
                "icmp_enabled": False,
                "tcp_halfopen_enabled": False,
                "doh_noise_enabled": False,
                "adaptive_intensity": False,
            }
        })

        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"OK"
        mock_session.get.return_value = mock_response

        distractor = RussianDistractor(config)
        self.assertTrue(distractor.running)

        time.sleep(0.5)
        distractor.stop()

        self.assertFalse(distractor.running)

    def test_get_adjusted_pause_no_adaptive(self):
        """Без адаптивности пауза должна быть в базовом диапазоне."""
        config = _deep_merge(DEFAULT_CONFIG, {
            "distractor": {
                "min_pause": 10,
                "max_pause": 100,
                "icmp_enabled": False,
                "tcp_halfopen_enabled": False,
                "doh_noise_enabled": False,
                "adaptive_intensity": False,
            }
        })

        with patch("dpi_evader.HAS_REQUESTS", False), \
             patch("dpi_evader.HAS_SCAPY", False):
            distractor = RussianDistractor(config)

        for _ in range(50):
            pause = distractor._get_adjusted_pause()
            self.assertGreaterEqual(pause, 10)
            self.assertLessEqual(pause, 100)

        distractor.stop()


class TestDeepMerge(unittest.TestCase):

    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        self.assertEqual(result, {"a": 1, "b": 3, "c": 4})

    def test_nested_merge(self):
        base = {"x": {"a": 1, "b": 2}, "y": 3}
        override = {"x": {"b": 99, "c": 100}}
        result = _deep_merge(base, override)
        self.assertEqual(result, {"x": {"a": 1, "b": 99, "c": 100}, "y": 3})


if __name__ == "__main__":
    unittest.main()
