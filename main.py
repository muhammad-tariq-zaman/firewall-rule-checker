"""Check firewall rules for overly open rules.

Input format, one rule per line:
  <ALLOW|DENY> <tcp|udp|any> <port|any> from <any|IP|CIDR>
Usage: python3 main.py rules.txt
"""
import argparse
import sys


def parse_rule(line):
    parts = line.strip().split()
    if len(parts) != 5 or parts[3].lower() != "from":
        raise ValueError(f"Invalid rule line: {line!r}")
    return {"action": parts[0].upper(), "proto": parts[1].lower(),
            "port": parts[2].lower(), "source": parts[4].lower()}


def audit_rules(rules):
    """Return findings: (severity, rule, message)."""
    findings = []
    for rule in rules:
        if rule["action"] != "ALLOW":
            continue
        if rule["source"] == "any" and rule["port"] == "any":
            findings.append(("CRITICAL", rule, "allows any source to any port"))
        elif rule["source"] == "any" and rule["port"] in ("22", "3389"):
            findings.append(("REVIEW", rule,
                             "allows any source to a remote-admin port"))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Path to a rules file")
    args = parser.parse_args(argv)
    rules = []
    with open(args.path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(parse_rule(line))
    findings = audit_rules(rules)
    print(f"Checked {len(rules)} rule(s), {len(findings)} finding(s).")
    for severity, rule, message in findings:
        print(f"- [{severity}] {rule['action']} {rule['proto']} {rule['port']} "
              f"from {rule['source']}: {message}")
    return 1 if any(s == "CRITICAL" for s, _, _ in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
