"""The corpus auditor must provision the same prerequisites as a consumer."""

from pathlib import Path
import importlib.util

import yaml


spec = importlib.util.spec_from_file_location(
    "audit_corpus", Path(__file__).parents[1] / "tools" / "audit_corpus.py"
)
audit_corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_corpus)


def test_audit_provisions_keyword_text_and_correlation_dependencies(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    detection = {
        "title": "Keyword base",
        "name": "keyword_base",
        "logsource": {"category": "test"},
        "detection": {"selection": ["event::clear"], "condition": "selection"},
    }
    correlation = {
        "title": "Keyword correlation",
        "correlation": {
            "type": "event_count",
            "rules": ["keyword_base"],
            "timespan": "5m",
            "condition": {"gte": 1},
        },
    }
    (rules / "keywords.yml").write_text(yaml.safe_dump_all([detection, correlation]))
    result = audit_corpus.audit(tmp_path, "raw", fulltext_field="_sigma_fulltext")
    assert result["errors"] == []
    assert result["counts"]["converted_rules"] == 2
    assert result["counts"]["prepared_queries"] == 1
    assert result["counts"]["fulltext_queries"] == 1
    assert result["fulltext_field"] == "_sigma_fulltext"


def test_audit_keyword_configuration_is_explicit(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "keywords.yml").write_text(
        "title: Keyword\nlogsource: {category: test}\n"
        "detection:\n  selection: ['event::clear']\n  condition: selection\n"
    )
    result = audit_corpus.audit(tmp_path, "raw")
    assert len(result["errors"]) == 1
    assert result["errors"][0]["stage"] == "conversion"
