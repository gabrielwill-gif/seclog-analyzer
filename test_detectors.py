import unittest
from pathlib import Path

from seclog.detectors import Thresholds, analyze
from seclog.parsers import parse_line

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(*names):
    events = []
    for name in names:
        for line in (SAMPLES / name).read_text(encoding="utf-8").splitlines():
            ev = parse_line(line, 2026)
            if ev:
                events.append(ev)
    return events


def rules_for(alerts, ip):
    return {a.rule for a in alerts if a.ip == ip}


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alerts = analyze(load("auth.log", "access.log"), Thresholds())

    def test_ssh_bruteforce_detected(self):
        self.assertIn("ssh_bruteforce", rules_for(self.alerts, "203.0.113.5"))

    def test_user_enumeration_detected(self):
        self.assertIn("ssh_user_enumeration", rules_for(self.alerts, "203.0.113.5"))

    def test_success_after_failures_is_critical(self):
        crit = [a for a in self.alerts if a.rule == "ssh_success_after_failures"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0].severity, "CRITICAL")
        self.assertEqual(crit[0].ip, "198.51.100.7")

    def test_web_attacks_detected(self):
        rules = rules_for(self.alerts, "203.0.113.9")
        for expected in ("web_sql_injection", "web_path_traversal", "web_xss",
                         "scanner_user_agent"):
            self.assertIn(expected, rules)

    def test_directory_scan_detected(self):
        self.assertIn("directory_scan", rules_for(self.alerts, "198.51.100.23"))

    def test_legitimate_user_has_no_alerts(self):
        self.assertEqual(rules_for(self.alerts, "192.0.2.10"), set())

    def test_alerts_sorted_by_severity(self):
        self.assertEqual(self.alerts[0].severity, "CRITICAL")

    def test_higher_threshold_reduces_alerts(self):
        strict = analyze(load("auth.log"), Thresholds(ssh_failures=50))
        self.assertFalse([a for a in strict if a.rule == "ssh_bruteforce"])


if __name__ == "__main__":
    unittest.main()
