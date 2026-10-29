import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from main import parse_rule, audit_rules


class TestFirewallChecker(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_rule("ALLOW tcp 22 from any")["port"], "22")

    def test_critical_any_any(self):
        findings = audit_rules([parse_rule("ALLOW any any from any")])
        self.assertEqual(findings[0][0], "CRITICAL")

    def test_review_ssh_from_any(self):
        findings = audit_rules([parse_rule("ALLOW tcp 22 from any")])
        self.assertEqual(findings[0][0], "REVIEW")

    def test_restricted_rule_clean(self):
        findings = audit_rules([parse_rule("ALLOW tcp 22 from 192.168.1.0/24")])
        self.assertEqual(findings, [])

    def test_deny_ignored(self):
        findings = audit_rules([parse_rule("DENY any any from any")])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
