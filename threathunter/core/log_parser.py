# log_parser.py
# Handles parsing of various log formats (auth.log, access.log, etc.)

import re
from typing import List, Dict

class LogParser:
    def __init__(self, log_type):
        self.log_type = log_type

    def parse(self, file_path) -> List[Dict]:
        if self.log_type == 'auth':
            return self._parse_auth_log(file_path)
        # TODO: Add support for syslog, access.log
        raise NotImplementedError(f"Log type {self.log_type} not supported yet.")

    def _parse_auth_log(self, file_path) -> List[Dict]:
        events = []
        # Example line: Jun  1 12:34:56 ubuntu sshd[12345]: Failed password for invalid user admin from 192.168.1.10 port 54321 ssh2
        pattern = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$')
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                match = pattern.match(line)
                if not match:
                    continue
                timestamp, host, process, pid, message = match.groups()
                event = {
                    'timestamp': timestamp,
                    'host': host,
                    'process': process,
                    'pid': pid,
                    'raw_message': message,
                }
                # Extract event_type, user, src_ip, details from message
                # Failed password
                failed = re.match(r'Failed password for (invalid user )?(\w+) from ([\d.]+)', message)
                accepted = re.match(r'Accepted password for (\w+) from ([\d.]+)', message)
                sudo = re.match(r'sudo: +([\w-]+) : (.*)', message)
                if failed:
                    event['event_type'] = 'Failed password'
                    event['user'] = failed.group(2)
                    event['src_ip'] = failed.group(3)
                elif accepted:
                    event['event_type'] = 'Accepted password'
                    event['user'] = accepted.group(1)
                    event['src_ip'] = accepted.group(2)
                elif sudo:
                    event['event_type'] = 'sudo'
                    event['user'] = sudo.group(1)
                    event['details'] = sudo.group(2)
                else:
                    event['event_type'] = 'other'
                events.append(event)
        return events 