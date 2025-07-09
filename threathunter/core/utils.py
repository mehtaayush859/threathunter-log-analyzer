# utils.py
# Utility functions for ThreatHunter

import logging
import yaml
from typing import Any

logger = logging.getLogger(__name__)

def load_yaml(path: str) -> Any:
    """
    Load a YAML file and return its contents.
    Args:
        path (str): Path to the YAML file.
    Returns:
        Any: Parsed YAML content.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        logger.info(f"Loaded YAML file: {path}")
        return data
    except Exception as e:
        logger.error(f"Failed to load YAML file {path}: {e}")
        return None 