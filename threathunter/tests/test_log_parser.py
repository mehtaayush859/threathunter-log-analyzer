# test_log_parser.py
import pytest
from threathunter.core.log_parser import LogParser

def test_log_parser_init():
    parser = LogParser('auth')
    assert parser.log_type == 'auth' 