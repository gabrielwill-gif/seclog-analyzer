import unittest

from seclog.parsers import parse_line

YEAR = 2026


class ParserTests(unittest.TestCase):
    def test_ssh_failed_invalid_user(self):
        ev = parse_line(
            "Nov 13 02:14:01 srv sshd[1]: Failed password for invalid user admin "
            "from 203.0.113.5 port 4444 ssh2", YEAR)
        self.assertEqual(ev.kind, "ssh_failed")
        self.assertEqual(ev.ip, "203.0.113.5")
        self.assertEqual(ev.user, "admin")

    def test_ssh_success(self):
        ev = parse_line(
            "Nov  3 08:00:00 srv sshd[2]: Accepted publickey for gabriel "
            "from 192.0.2.10 port 22 ssh2", YEAR)
        self.assertEqual(ev.kind, "ssh_success")
        self.assertEqual(ev.timestamp.day, 3)

    def test_http_line_with_spaces_in_path(self):
        ev = parse_line(
            '203.0.113.9 - - [13/Nov/2026:02:15:01 +0000] "GET /x?id=1\' OR \'1\'=\'1 HTTP/1.1" '
            '500 10 "-" "sqlmap/1.7"', YEAR)
        self.assertEqual(ev.kind, "http")
        self.assertEqual(ev.status, 500)
        self.assertIn("OR", ev.path)
        self.assertEqual(ev.user_agent, "sqlmap/1.7")

    def test_unknown_line_returns_none(self):
        self.assertIsNone(parse_line("linha qualquer sem formato", YEAR))


if __name__ == "__main__":
    unittest.main()
