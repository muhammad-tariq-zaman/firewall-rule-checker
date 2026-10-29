# firewall-rule-checker

Check a list of firewall rules for overly open entries. Rules use one
line each: `ALLOW tcp 22 from any`. A rule that allows any source to
any port is CRITICAL; any source to SSH (22) or RDP (3389) is flagged
for review.

## How to run

```bash
python3 main.py rules.txt
```

## Example output

```text
Checked 3 rule(s), 2 finding(s).
- [CRITICAL] ALLOW any any from any: allows any source to any port
- [REVIEW] ALLOW tcp 22 from any: allows any source to a remote-admin port
```

Standard library only. No network access.
