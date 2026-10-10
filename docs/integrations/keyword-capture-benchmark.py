"""Optional benchmark requiring the companion Zircolite change.

Usage: python keyword-capture-benchmark.py {prepare,off,on} /tmp/keyword-benchmark
Run prepare once, then off/on in separate processes. Paths contain synthetic data.
"""

import json
import logging
import resource
import statistics
import sys
import time
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend
from zircolite import ProcessingConfig, ZircoliteCore

if len(sys.argv) != 3 or sys.argv[1] not in {"prepare", "off", "on"}:
    raise SystemExit(__doc__)
root = Path(sys.argv[2])
root.mkdir(parents=True, exist_ok=True)
source = root / "benchmark.jsonl"
config = root / "benchmark-config.json"
if sys.argv[1] == "prepare":
    config.write_text(
        json.dumps(
            {
                "exclusions": [],
                "useless": [None, ""],
                "mappings": {},
                "alias": {},
                "split": {},
                "transforms_enabled": False,
                "transforms": {},
            }
        )
    )
    with source.open("w") as stream:
        for i in range(100000):
            event = {
                "EventID": 1,
                "RecordId": i,
                "Image": "/usr/bin/bash",
                "CommandLine": (
                    "run --job=keywordneedle" if i % 1000 == 0 else "run --job=normal"
                ),
                "Payload": "x" * 400,
                "nested": {"user": "operator", "tags": ["linux", "process"]},
            }
            stream.write(json.dumps(event) + "\n")
    print(json.dumps({"rows": 100000, "source_bytes": source.stat().st_size}))
    raise SystemExit
capture = sys.argv[1] == "on"
logger = logging.getLogger("benchmark")
logger.addHandler(logging.NullHandler())
logger.setLevel(logging.CRITICAL)
rule = json.loads(
    sqliteBackend(fulltext_field="_sigma_fulltext").convert(
        SigmaCollection.from_yaml(
            """title: Keyword benchmark
logsource:
  category: test
detection:
  keywords:
    - keywordneedle
  condition: keywords
"""
        ),
        output_format="zircolite",
    )
)[0]
core = ZircoliteCore(
    str(config),
    ProcessingConfig(
        fulltext_capture=capture, flatten_backend="auto", disable_progress=True
    ),
    logger=logger,
)
try:
    start = time.perf_counter()
    count = core.run_streaming([source], input_type="json", disable_progress=True)
    ingestion = time.perf_counter() - start
    assert count == 100000, count
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    size = (
        core.db_connection.execute("PRAGMA page_count").fetchone()[0]
        * core.db_connection.execute("PRAGMA page_size").fetchone()[0]
    )
    data = {
        "capture": capture,
        "rows": count,
        "ingestion_seconds": ingestion,
        "sqlite_bytes": size,
        "peak_rss_bytes_macos": peak,
        "flattening": core.metrics.data["flattening"],
    }
    if capture:
        start = time.perf_counter()
        assert core.execute_rule(rule)["count"] == 100
        data["first_query_seconds"] = time.perf_counter() - start
        durations = []
        for _ in range(5):
            start = time.perf_counter()
            assert core.execute_rule(rule)["count"] == 100
            durations.append(time.perf_counter() - start)
        data["cached_query_median_seconds"] = statistics.median(durations)
        data["search_text_bytes"] = core.db_connection.execute(
            "SELECT sum(length(CAST(_sigma_fulltext AS BLOB))) FROM logs"
        ).fetchone()[0]
    print(json.dumps(data))
finally:
    core.close()
