"""Exercise the pySigma contracts used by the backend without import shims."""

import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaModifiedError, SigmaRegularExpressionError
from sigma.policy.profiles import TrustedPolicy

from sigma.backends.sqlite import sqliteBackend


def rule(selection):
    return {
        "title": "Compatibility",
        "logsource": {"category": "test"},
        "detection": {"selection": selection, "condition": "selection"},
    }


def test_fresh_process_imports_and_discovers_checkout_backend():
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from sigma.backends.sqlite import sqliteBackend; "
            "from sigma.plugins import InstalledSigmaPlugins; "
            "assert InstalledSigmaPlugins.autodiscover().backends['sqlite'] is sqliteBackend",
        ],
        cwd=Path(__file__).parents[1],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("field", ["message", ""])
def test_explicit_regex_policy_preserves_python_patterns(field):
    collection = SigmaCollection.from_dicts(
        [rule({f"{field}|re|i": "foo(?=bar)"})], policy=TrustedPolicy
    )
    query = sqliteBackend(fulltext_field="message").convert(collection)[0]
    with sqlite3.connect(":memory:") as connection:
        connection.create_function(
            "regexp", 2, lambda p, v: v is not None and re.search(p, v) is not None
        )
        connection.execute("CREATE TABLE logs(message TEXT)")
        connection.executemany(
            "INSERT INTO logs VALUES (?)", [("FOObar",), ("fooqux",), (None,)]
        )
        assert connection.execute(query).fetchall() == [("FOObar",)]


@pytest.mark.parametrize("field", ["message", ""])
def test_default_regex_policy_rejects_python_only_patterns(field):
    with pytest.raises(SigmaRegularExpressionError):
        SigmaCollection.from_dicts([rule({f"{field}|re": "foo(?=bar)"})])


@pytest.mark.parametrize("field", ["message", ""])
def test_windash_expansion_boundary_matches_events(field):
    collection = SigmaCollection.from_dicts(
        [rule({f"{field}|windash": "-one -two -three"})]
    )
    query = sqliteBackend(fulltext_field="message").convert(collection)[0]
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE logs(message TEXT)")
        connection.executemany(
            "INSERT INTO logs VALUES (?)",
            [
                ("-one -two -three",),
                ("/one \u2013two \u2014three",),
                ("one two three",),
            ],
        )
        assert connection.execute(query).fetchall() == [
            ("-one -two -three",),
            ("/one \u2013two \u2014three",),
        ]


@pytest.mark.parametrize("field", ["message", ""])
def test_excessive_windash_expansion_is_not_silently_converted(field):
    with pytest.raises(SigmaModifiedError, match="at most three dash occurrences"):
        SigmaCollection.from_dicts([rule({f"{field}|windash": "-a -b -c -d"})])
