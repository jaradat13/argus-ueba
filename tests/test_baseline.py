import unittest

from argus_ueba.baseline import Baseline
from argus_ueba.parsers import parse_files


class BaselineTests(unittest.TestCase):
    def test_baseline_flags_off_hours_new_ip_and_dual_use_command(self):
        baseline = Baseline.from_events(parse_files(["samples/baseline.log"], year=2026))
        events = parse_files(["samples/events.log"], year=2026)

        findings = baseline.evaluate(events, threshold=50)

        self.assertTrue(findings)
        self.assertGreaterEqual(findings[0].score, 80)
        self.assertTrue(any("T1105 Ingress Tool Transfer" in finding.mitre_tags for finding in findings))
        self.assertTrue(any(finding.event.target == "/etc/shadow" for finding in findings))


if __name__ == "__main__":
    unittest.main()
