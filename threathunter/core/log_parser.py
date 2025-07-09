# log_parser.py
# Handles parsing of various log formats (auth.log, access.log, etc.)

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class LogParser:
    """
    Parses various log formats (auth.log, access.log, etc.) and returns structured events.
    """
    def __init__(self, log_type: str) -> None:
        """
        Initialize the LogParser.
        Args:
            log_type (str): The type of log to parse (e.g., 'auth').
        """
        self.log_type = log_type

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse the specified log file based on the log type.
        Args:
            file_path (str): Path to the log file.
        Returns:
            List[Dict[str, Any]]: List of parsed log events.
        """
        logger.info(f"Parsing log file: {file_path} as type: {self.log_type}")
        if self.log_type == 'auth':
            return self._parse_auth_log(file_path)
        # TODO: Add support for syslog, access.log
        logger.error(f"Log type {self.log_type} not supported yet.")
        raise NotImplementedError(f"Log type {self.log_type} not supported yet.")

    def _parse_auth_log(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse a Linux auth.log file and extract structured events.
        Args:
            file_path (str): Path to the auth.log file.
        Returns:
            List[Dict[str, Any]]: List of parsed log events.
        """
        events: List[Dict[str, Any]] = []
        pattern = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$')
        try:
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
            logger.info(f"Parsed {len(events)} events from {file_path}")
        except Exception as e:
            logger.error(f"Failed to parse auth log: {e}")
        return events 