import argparse
import json
import yaml
from threathunter.core.log_parser import LogParser
from threathunter.core.rule_engine import RuleEngine


def main():
    parser = argparse.ArgumentParser(description="ThreatHunter - Lightweight SIEM-like Log Analyzer")
    parser.add_argument('--config', type=str, default='config.yaml', help='Path to config file')
    parser.add_argument('--log', type=str, required=True, help='Path to log file (e.g., auth.log)')
    parser.add_argument('--logtype', type=str, default='auth', help='Type of log: auth, syslog, access')
    parser.add_argument('--rules', type=str, default='threathunter/alerts/alert_rules.yaml', help='Path to alert rules YAML')
    parser.add_argument('--alerts', type=str, default='threathunter/reports/alerts.json', help='Path to output alerts JSON')
    args = parser.parse_args()

    print("[+] ThreatHunter starting...")
    print(f"[+] Using config: {args.config}")
    print(f"[+] Parsing log: {args.log} (type: {args.logtype})")

    log_parser = LogParser(args.logtype)
    events = log_parser.parse(args.log)
    print(f"[+] Parsed {len(events)} events.")

    # Load rules
    with open(args.rules, 'r', encoding='utf-8') as f:
        rules = yaml.safe_load(f)
    print(f"[+] Loaded {len(rules)} alert rules.")

    # Evaluate rules
    rule_engine = RuleEngine(rules)
    alerts = rule_engine.evaluate(events)
    print(f"[+] Detected {len(alerts)} alerts.")

    # Output alerts to JSON
    with open(args.alerts, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=2)
    print(f"[+] Alerts written to {args.alerts}")

    # Print alert summary
    for alert in alerts:
        print(f"[ALERT] {alert['timestamp']} | {alert['rule']} | User: {alert.get('user')} | IP: {alert.get('src_ip')} | Severity: {alert['severity']}")

if __name__ == "__main__":
    main() 