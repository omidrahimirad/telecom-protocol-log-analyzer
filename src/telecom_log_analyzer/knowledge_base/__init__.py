"""Cause-code knowledge base."""

from telecom_log_analyzer.knowledge_base.loader import (
    CauseCodeCatalog,
    CauseCodeEntry,
    load_cause_catalog,
)

__all__ = ["CauseCodeCatalog", "CauseCodeEntry", "load_cause_catalog"]
