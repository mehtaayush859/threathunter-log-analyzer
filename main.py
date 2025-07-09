import argparse
import json
import yaml
import logging
from threathunter.core.log_parser import LogParser
from threathunter.core.rule_engine import RuleEngine


def main() -> None:
    """
    Main CLI entrypoint for ThreatHunter log analyzer.
    Parses logs, applies alert rules, and outputs alerts.
    """
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("threathunter.main")

    parser = argparse.ArgumentParser(description="ThreatHunter - Lightweight SIEM-like Log Analyzer")
    parser.add_argument('--config', type=str, default='config.yaml', help='Path to config file')
    parser.add_argument('--log', type=str, required=True, help='Path to log file (e.g., auth.log)')
    parser.add_argument('--logtype', type=str, default='auth', help='Type of log: auth, syslog, access')
    parser.add_argument('--rules', type=str, default='threathunter/alerts/alert_rules.yaml', help='Path to alert rules YAML')
    parser.add_argument('--alerts', type=str, default='threathunter/reports/alerts.json', help='Path to output alerts JSON')
    args = parser.parse_args()

    logger.info("ThreatHunter starting...")
    logger.info(f"Using config: {args.config}")
    logger.info(f"Parsing log: {args.log} (type: {args.logtype})")

    log_parser = LogParser(args.logtype)
    events = log_parser.parse(args.log)
    logger.info(f"Parsed {len(events)} events.")

    # Load rules
    try:
        with open(args.rules, 'r', encoding='utf-8') as f:
            rules = yaml.safe_load(f)
        logger.info(f"Loaded {len(rules)} alert rules.")
    except Exception as e:
        logger.error(f"Failed to load rules: {e}")
        return

    # Evaluate rules
    rule_engine = RuleEngine(rules)
    alerts = rule_engine.evaluate(events)
    logger.info(f"Detected {len(alerts)} alerts.")

    # Output alerts to JSON
    try:
        with open(args.alerts, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, indent=2)
        logger.info(f"Alerts written to {args.alerts}")
    except Exception as e:
        logger.error(f"Failed to write alerts: {e}")

    # Print alert summary
    for alert in alerts:
        logger.info(f"[ALERT] {alert['timestamp']} | {alert['rule']} | User: {alert.get('user')} | IP: {alert.get('src_ip')} | Severity: {alert['severity']}")

if __name__ == "__main__":
    main() 