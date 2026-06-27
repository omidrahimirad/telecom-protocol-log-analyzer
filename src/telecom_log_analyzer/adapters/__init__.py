"""Decoded trace input adapters."""

from telecom_log_analyzer.adapters.base import AdapterResult, InputAdapter, detect_input_format
from telecom_log_analyzer.adapters.jsonl import JsonlAdapter
from telecom_log_analyzer.adapters.simplified_text import SimplifiedTextAdapter
from telecom_log_analyzer.adapters.tshark_json import TsharkJsonAdapter

__all__ = [
    "AdapterResult",
    "InputAdapter",
    "JsonlAdapter",
    "SimplifiedTextAdapter",
    "TsharkJsonAdapter",
    "detect_input_format",
]
