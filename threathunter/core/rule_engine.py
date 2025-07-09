# rule_engine.py
# Handles rule-based detection logic

import re
import time
import logging
from collections import defaultdict
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class RuleEngine:
    """
    Evaluates log events against detection rules and generates alerts.
    """
    def __init__(self, rules: List[Dict[str, Any]]) -> None:
        """
        Initialize the RuleEngine.
        Args:
            rules (List[Dict[str, Any]]): List of detection rules.
        """
        self.rules = rules

    def evaluate(self, log_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluate log events against the loaded rules and generate alerts.
        Args:
            log_events (List[Dict[str, Any]]): List of parsed log events.
        Returns:
            List[Dict[str, Any]]: List of generated alerts.
        """
        alerts: List[Dict[str, Any]] = []
        logger.info(f"Evaluating {len(log_events)} events against {len(self.rules)} rules.")
        for rule in self.rules:
            log_type = rule.get('log_type')
            matches = rule.get('match', [])
            severity = rule.get('severity', 'Low')
            name = rule.get('name', 'Unnamed Rule')
            # Filter events by log_type if needed
            filtered_events = [e for e in log_events if log_type is None or e.get('process') or log_type in e.get('process', '')]
            for match in matches:
                pattern = match.get('pattern')
                count = match.get('count', 1)
                timeframe = match.get('timeframe', None)
                user_cond = match.get('user', None)
                # Find events matching the pattern
                matched_events = [e for e in filtered_events if pattern and pattern in e.get('raw_message', '')]
                # User-based filtering
                if user_cond:
                    if user_cond == 'not root':
                        matched_events = [e for e in matched_events if e.get('user') and e['user'] != 'root']
                    else:
                        matched_events = [e for e in matched_events if e.get('user') == user_cond]
                # Time-based threshold
                if timeframe and count > 1:
                    # Group by user+src_ip
                    buckets = defaultdict(list)
                    for e in matched_events:
                        key = (e.get('user'), e.get('src_ip'))
                        buckets[key].append(e)
                    for key, events in buckets.items():
                        # Sort by timestamp (convert to epoch for comparison)
                        def to_epoch(ts: str) -> float:
                            try:
                                return time.mktime(time.strptime(ts, '%b %d %H:%M:%S'))
                            except Exception:
                                return 0
                        events = sorted(events, key=lambda x: to_epoch(x['timestamp']))
                        for i in range(len(events) - count + 1):
                            t0 = to_epoch(events[i]['timestamp'])
                            t1 = to_epoch(events[i+count-1]['timestamp'])
                            if t1 - t0 <= timeframe:
                                alert = {
                                    'timestamp': events[i+count-1]['timestamp'],
                                    'rule': name,
                                    'user': key[0],
                                    'src_ip': key[1],
                                    'severity': severity,
                                    'events': events[i:i+count],
                                }
                                alerts.append(alert)
                                logger.info(f"Alert triggered: {alert}")
                else:
                    # Single event match
                    for e in matched_events:
                        alert = {
                            'timestamp': e['timestamp'],
                            'rule': name,
                            'user': e.get('user'),
                            'src_ip': e.get('src_ip'),
                            'severity': severity,
                            'event': e,
                        }
                        alerts.append(alert)
                        logger.info(f"Alert triggered: {alert}")
        logger.info(f"Total alerts generated: {len(alerts)}")
        return alerts 