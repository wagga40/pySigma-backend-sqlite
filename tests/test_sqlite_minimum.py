"""Run the actual generated statements on the supported minimum SQLite CLI."""

import json
import os
import runpy
import subprocess
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection

from sigma.backends.sqlite import sqliteBackend

sqlite_cli = os.environ.get("SQLITE_MIN_BINARY")
pytestmark = pytest.mark.skipif(
    not sqlite_cli, reason="Set SQLITE_MIN_BINARY to the SQLite 3.38 CLI"
)
helpers = runpy.run_path(str(Path(__file__).with_name("test_correlations.py")))


def execute_minimum(docs, events, materialized):
    entry = json.loads(
        sqliteBackend(event_id_field="row_id").convert(
            SigmaCollection.from_dicts(docs), "zircolite"
        )
    )[-1]
    con = helpers["database"](events)
    script = "\n".join(con.iterdump()) + "\n"
    con.close()
    if materialized:
        plan = entry["correlation_plan"]
        for stage in plan["prepare"]:
            script += f"CREATE TEMP TABLE {stage['name']} AS {stage['select']};\n"
            for i, columns in enumerate(stage["indexes"]):
                script += f"CREATE INDEX {stage['name']}_i{i} ON {stage['name']} ({','.join(columns)});\n"
        script += plan["query"] + ";"
    else:
        script += entry["rule"][0] + ";"
    result = subprocess.run(
        [sqlite_cli, "-json", ":memory:"],
        input=script,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout or "[]")


@pytest.mark.parametrize(
    "kind",
    [
        "event_count",
        "value_count",
        "value_sum",
        "value_avg",
        "value_median",
        "value_percentile",
        "temporal",
        "temporal_ordered",
    ],
)
@pytest.mark.parametrize("materialized", [False, True])
def test_minimum_sqlite_executes_correlations(kind, materialized):
    cond = {"gte": 1}
    if kind.startswith("value_"):
        cond["field"] = "Bytes"
    if kind == "value_percentile":
        cond["percentile"] = 50
    refs = ("a", "b") if kind.startswith("temporal") else ("a",)
    docs = [
        helpers["detection"](),
        helpers["detection"]("b", 2),
        helpers["correlation"](kind, refs, cond),
    ]
    events = [
        helpers["event"](0, Bytes="10"),
        helpers["event"](0.5, Bytes="20"),
        helpers["event"](1, EventID=2),
    ]
    rows = execute_minimum(docs, events, materialized)
    expected = helpers["execute"](docs, events)
    assert [r["metric_value"] for r in rows] == [r["metric_value"] for r in expected]
    assert [json.loads(r["event_ids"]) for r in rows] == [
        r["event_ids"] for r in expected
    ]


@pytest.mark.parametrize("materialized", [False, True])
@pytest.mark.parametrize(
    "case",
    [
        "count-success",
        "child-metric",
        "absence-chain",
        "regroup",
        "zero-count",
        "partial-order",
        "pure-absence",
        "overlap",
    ],
)
def test_minimum_sqlite_correlation_regressions(case, materialized):
    detection, correlation, event = (
        helpers[name] for name in ("detection", "correlation", "event")
    )
    docs = [detection(), correlation(name="burst")]
    events = [event(0), event(1)]
    if case == "count-success":
        docs += [
            detection("success", 2),
            correlation("temporal_ordered", ("burst", "success")),
        ]
        events += [event(2, EventID=2)]
        metrics, evidence = [2], [["0:1", "0:2", "0:3"]]
    elif case == "child-metric":
        docs += [
            correlation("value_sum", ("burst",), {"gte": 2, "field": "event_count"})
        ]
        metrics, evidence = [2], [["0:1", "0:2"]]
    elif case == "absence-chain":
        docs = [
            detection(),
            detection("b", 2),
            detection("c", 3),
            correlation("temporal_ordered", ("a", "b"), "a and not b", name="absent"),
            correlation("temporal_ordered", ("absent", "c")),
        ]
        events = [event(0), event(6, EventID=3)]
        metrics, evidence = [2], [["0:1", "0:2"]]
    elif case == "regroup":
        docs += [
            correlation("event_count", ("burst",), {"gte": 1}, **{"group-by": ["User"]})
        ]
        events = [event(0, User="alice"), event(1, User="bob")]
        metrics, evidence = [1, 1], [["0:1", "0:2"], ["0:1", "0:2"]]
    elif case == "zero-count":
        docs = [
            detection(),
            correlation(
                "value_count", condition={"eq": 0, "field": "User"}, name="no_users"
            ),
            correlation("event_count", ("no_users",), {"gte": 1}),
        ]
        events = [event(0, User=None)]
        metrics, evidence = [1], [["0:1"]]
    elif case == "partial-order":
        docs = [
            detection(),
            detection("b", 2),
            detection("c", 3),
            correlation("temporal_ordered", ("a", "b", "c"), {"gte": 2}),
        ]
        events = [event(0, EventID=3), event(1), event(2, EventID=2)]
        metrics, evidence = [3], [["0:2", "0:3"]]
    elif case == "pure-absence":
        docs = [detection(), correlation("temporal", condition="not a")]
        events = [event(0, EventID=99), event(5, EventID=99)]
        metrics, evidence = [0], [["0:1"]]
    else:
        docs = [
            detection(),
            detection("b", 2),
            correlation("temporal", ("a", "b"), "a or b"),
        ]
        events = [event(0), event(0, EventID=2)]
        metrics, evidence = [2], [["0:1", "0:2"]]
    rows = execute_minimum(docs, events, materialized)
    assert [row["metric_value"] for row in rows] == metrics
    assert [json.loads(row["event_ids"]) for row in rows] == evidence
    expected = helpers["execute"](docs, events, materialized=True)
    for actual, reference in zip(rows, expected, strict=True):
        assert json.loads(actual["group_keys"]) == reference["group_keys"]
        assert json.loads(actual["child_alert_ids"]) == reference["child_alert_ids"]
        assert actual["alert_id"] == reference["alert_id"]
        for field in ("window_start", "window_end", "occurrence_time"):
            assert actual[field] == pytest.approx(reference[field], abs=1e-6, rel=0)


@pytest.mark.parametrize("materialized", [False, True])
def test_minimum_sqlite_executes_keyword_correlation(materialized):
    docs = [
        {
            "title": "keyword",
            "name": "keyword",
            "logsource": {"category": "test"},
            "detection": {"selection": ["needle"], "condition": "selection"},
        },
        {
            "title": "burst",
            "name": "burst",
            "correlation": {
                "type": "event_count",
                "rules": ["keyword"],
                "timespan": "5s",
                "group-by": ["Host"],
                "condition": {"gte": 1},
            },
        },
    ]
    entry = json.loads(
        sqliteBackend(fulltext_field="_sigma_fulltext").convert(
            SigmaCollection.from_yaml(yaml.safe_dump_all(docs)), "zircolite"
        )
    )[-1]
    plan = entry["correlation_plan"]
    assert plan["version"] == 3
    script = (
        "CREATE TABLE logs (timestamp TEXT, Host TEXT, _sigma_fulltext TEXT);\n"
        "INSERT INTO logs VALUES ('2024-01-01T00:00:00', 'h', 'a needle b');\n"
    )
    if materialized:
        for stage in plan["prepare"]:
            script += f"CREATE TEMP TABLE {stage['name']} AS {stage['select']};\n"
            for i, columns in enumerate(stage["indexes"]):
                script += f"CREATE INDEX {stage['name']}_i{i} ON {stage['name']} ({','.join(columns)});\n"
        script += plan["query"] + ";"
    else:
        script += entry["rule"][0] + ";"
    result = subprocess.run(
        [sqlite_cli, "-json", ":memory:"],
        input=script,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)[0]["metric_value"] == 1
