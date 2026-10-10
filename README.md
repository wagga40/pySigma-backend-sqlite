![Tests](https://github.com/wagga40/pySigma-backend-sqlite/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/wagga40/2ec45ded898fa11f2c42bcb9d2b163cf/raw/test.json)

# pySigma SQLite Backend

Converts [Sigma](https://github.com/SigmaHQ/sigma) rules into SQLite queries. The
package `sigma.backends.sqlite` provides `sqliteBackend`, registered as the
sigma-cli target `sqlite`. It is the converter behind
[Zircolite](https://github.com/wagga40/Zircolite), and its output runs on any
SQLite table of flattened events.

Maintained by [wagga](https://github.com/wagga40/).

## Install

```shell
pip install pysigma-backend-sqlite
```

Requires Python 3.11+ and [pySigma](https://github.com/SigmaHQ/pySigma) 2.x.
Backend 2.0.0 is the last release for pySigma 1.5. Correlation output needs
SQLite 3.38 or newer.

## Quick start

```python
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

rules = SigmaCollection.from_yaml(r"""
title: Whoami execution
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
""")

print(sqliteBackend().convert(rules)[0])
# SELECT * FROM logs WHERE Image LIKE '%\\whoami.exe' ESCAPE '\'
```

Processing pipelines map a logsource to concrete fields. With
`sqliteBackend(sysmon_pipeline() + windows_logsource_pipeline())` the same rule becomes:

```sql
SELECT * FROM logs WHERE Channel='Microsoft-Windows-Sysmon/Operational' AND (EventID=1 AND Image LIKE '%\\whoami.exe' ESCAPE '\')
```

Those pipeline packages still declare `pysigma<2`; until they are updated, install
them with `pip install --no-deps pysigma-pipeline-sysmon pysigma-pipeline-windows`.
With sigma-cli:

```shell
sigma convert -t sqlite -f zircolite -p sysmon -p windows-logsources rules/
```

sigma-cli 3.1 still requires pySigma 1.x, so it installs backend 2.0.0.

## Output formats

| Format | Output |
|---|---|
| `default` | One `SELECT * FROM logs WHERE ...` statement per rule |
| `zircolite` | A JSON list with one entry per rule: Sigma metadata, the SQL, and what a consumer needs to run it. See [output format](docs/output-format.md) |

## Options

Pass options as constructor keywords, or from sigma-cli with `-O name=value`.
Options are read at construction; assigning attributes later skips validation
and does not change the timestamp expression.

| Option | Default | Purpose |
|---|---|---|
| `table` | `logs` | Table to query. A pipeline `setState` on `table` takes precedence |
| `collate_nocase` | `false` | Emit `field='value' COLLATE NOCASE` for tables without `NOCASE` columns |
| `max_flat_operands` | `100` | Longer AND/OR chains are nested to stay under SQLite's expression depth limit |
| `fulltext_field` | none | Column of searchable event text; enables [keyword search](docs/keyword-search.md) |
| `timestamp_field` | `timestamp` | Event time column used by correlations |
| `timestamp_format` | `iso` | `iso`, `unix`, `unix_ms` or `unix_us` |
| `timestamp_seconds_expression` | ISO parser | SQL turning `{field}` into Unix seconds; overrides `timestamp_format` |
| `event_id_field` | `rowid` | Non-NULL, per-table unique event identifier for correlation evidence |
| `observation_end` | latest event | Unix seconds up to which absence windows can expire |

## Generated SQL

| Modifier | SQL |
|---|---|
| `contains`, `startswith`, `endswith` | `LIKE '%value%' ESCAPE '\'` and its prefix/suffix forms |
| `all` | `AND` of the values |
| `re` | `REGEXP` (needs a registered function, see [Limitations](#limitations)) |
| `cidr` | `=` or `LIKE` prefixes of the expanded network |
| `cased` | `GLOB`; literal `*`, `?`, `[` become `[*]`, `[?]`, `[[]` |
| `fieldref` | `field1=field2`, or `LIKE` with the second field's `%` and `_` escaped |
| `exists` | `IS NOT NULL` / `IS NULL` |
| `gt`, `gte`, `lt`, `lte`, `neq` | `>`, `>=`, `<`, `<=`, negated equality |
| `minute`, `hour`, `day`, `week`, `month`, `year` | `strftime()` part |
| `base64`, `base64offset`, `wide`, `utf16*`, `windash` | Expanded by pySigma into ordinary matches |

The SQL keeps Sigma's meaning without help from the caller:

- **Negation.** Sigma reads a condition on a missing field as false; SQLite reads
  it as `NULL`, and `NOT NULL` drops the row. Every `NOT` therefore wraps its
  operand: `EventID=1 AND (NOT COALESCE((CommandLine LIKE '%foo%' ESCAPE '\'), 0))`.
- **Case.** `LIKE` ignores case. `=` does only on `NOCASE` columns, which is how
  Zircolite builds its table; otherwise set `collate_nocase`. `cased` uses `GLOB`.
- **Booleans.** `Flag: true` matches text or integer storage: `(Flag='true' OR Flag=1)`.
- **Long lists.** Chains above `max_flat_operands` are regrouped, so rules with
  thousands of values don't fail with "Expression tree is too large".
- **Field names.** SQLite keywords and names with characters other than letters,
  digits and `_` are quoted with backticks. `field: null` becomes `field IS NULL`.

## Correlations

All Sigma correlation types run in SQLite: `event_count`, `value_count`,
`value_sum`, `value_avg`, `value_median`, `value_percentile`, `temporal` and
`temporal_ordered`, including chains, aliases and extended temporal conditions.
Each result row is one alert occurrence with its window, metric and contributing
event IDs. Semantics are described in [correlations](docs/correlations.md);
upgrading from backend 1.x is covered in the [migration guide](docs/migration-v2.md).

## Keyword search

Keyword (fieldless) selections need a column of searchable event text:
`sqliteBackend(fulltext_field="_sigma_fulltext")`. Without it, keyword rules raise
an error rather than guess. See [keyword search](docs/keyword-search.md).

## Limitations

- **REGEXP.** SQLite has no built-in `REGEXP`. Register one that is false for `NULL`:
  `connection.create_function("regexp", 2, lambda p, v: v is not None and re.search(p, str(v)) is not None)`.
  pySigma 2 validates `|re` patterns with RE2, so rules with lookarounds or
  backreferences are rejected when parsed.
- **CIDR.** SQLite has no network type. Prefix patterns match IPv6 addresses only
  in the spellings pySigma expands to.
- **Case folding** (`NOCASE`, `LIKE`) is ASCII only.
- **Timestamp parts** use `strftime()` and need ISO-8601 text; a numeric epoch is
  read as a Julian day. `%W` can return week 0.
- **Field existence.** SQL `NULL` cannot tell a missing field from an explicit null.
- **Multi-field `value_count`** (a list in `condition.field`) is rejected.
- **Unknown columns.** A query naming a column the table lacks fails to prepare.
  Add missing columns as `NULL` first; see [output format](docs/output-format.md).

## Development

```shell
poetry install
poetry run pytest
SQLITE_MIN_BINARY=/path/to/sqlite-3.38 poetry run pytest tests/test_sqlite_minimum.py
```

`tools/audit_corpus.py` converts and prepares a SigmaHQ checkout per profile
(coverage, not detection accuracy). `tools/benchmark_correlations.py` times
sparse and dense correlation windows.
