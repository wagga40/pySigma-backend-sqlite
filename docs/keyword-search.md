# Keyword search

Keyword support uses standard SQLite predicates over original decoded event
values. Enable it with `sqliteBackend(fulltext_field="_sigma_fulltext")` and
populate that column before executing the generated queries. Without the option,
keyword conversion raises an actionable error.

`LIKE ... ESCAPE` preserves Sigma substring and wildcard behavior, including
punctuation and literal SQL wildcard characters. Fieldless `|cased` uses GLOB;
`|re` requires the consumer's REGEXP function. FTS5 token matching would change
substring and punctuation semantics, so this implementation does not use it.

## Contracts

- Backend option `fulltext_field: str | None = None`; Zircolite passes `_sigma_fulltext`.
- Requirement metadata key `fulltext`: a list of objects such as `{"table": "logs", "field": "_sigma_fulltext", "representation": "source-values-v1"}`. Table uses the backend's resolved/quoted name; field is the raw column name. Deduplicate and sort by table/field.
- Only text-dependent entries use `schema_version: 3`; only text-dependent correlation plans use `version: 3`. Preserve version 2 elsewhere. Correlation entries and plans carry identical requirements. All condition branches of a rule share its union of requirements.
- `sigma.backends.sqlite.runtime.validate_fulltext(connection, requirements)` validates shape, representation, column existence and non-NULL TEXT coverage before widening. Unavailable text raises an actionable `ValueError`. Generic callers provision their own text; the helper does not require Zircolite provenance. Version-3 plans require nonempty requirements.
- Strings and numbers use substring predicates with Sigma wildcards and escaping. Fieldless cased uses GLOB; regex uses existing REGEXP flags. Reuse AND/OR/NOT handling.
- Zircolite captures before flattening and generated metadata: dictionaries sorted by key, arrays in order, strings preserved, booleans lowercase, numbers converted with `str`, null omitted, newline-separated values. Empty content is empty text, not NULL. Include fields later excluded or transformed. Reject source/mapped reserved-name collisions rather than overwriting them.
- Persist provenance in `_zircolite_fulltext` (source_table TEXT PRIMARY KEY, field TEXT NOT NULL, representation TEXT NOT NULL). Its logs row records `logs`, `_sigma_fulltext`, `source-values-v1`. Manage it only when capture is enabled and reset it with logs; fail on unrelated table collisions.
- Enable capture when any loaded rule/dependency requires it, including per-file, unified, worker and native paths. Preserve text/provenance through backup/load. Old databases require re-ingestion for dependent rules; independent rules continue. Validate provenance/completeness once per content revision and invalidate on insert/reset/load.
- Omit internal text from displayed/exported matches and correlation evidence. Preserve conservative event filtering and merge requirements/schema versions across condition-list branches.

## Consumer integration

For generic SQLite consumers, use the `zircolite` output format to obtain the
prerequisite metadata, even when Zircolite itself is not used. After ingesting
source text, call `validate_fulltext(connection, entry["fulltext"])` for each
dependent ordinary rule before provisioning other absent columns or running SQL.
`execute_plan` performs this check itself for version-3 correlation plans.
The helper verifies TEXT coverage; the caller remains responsible for the
meaning of the supplied values.

The [companion Zircolite change](integrations/zircolite-keyword-search.md)
enables capture automatically when loaded rules require it, including correlation
dependencies. Library callers can load those rules before `run_streaming`, or
pass `ProcessingConfig(fulltext_capture=True)` explicitly. Captured databases
retain the text and representation marker through backup and reload. Old
databases remain usable for independent rules; keyword rules report that
re-ingestion is required.

Capture duplicates source values in the SQLite database, including values that
flattening would discard. Database size and ingestion memory therefore increase.
Keep this in mind when sharing captured databases. Normal results and flattened
exports omit this internal column. Substring predicates scan eligible rows;
ordinary B-tree indexes on the text do not accelerate leading-wildcard searches.
FTS5 indexing and the unrelated compatibility gaps below remain future work.

## Other Sigma compatibility limits

Keyword support does not imply complete conformance. The implementation was
compared with the published Sigma 2.1.0
[rules](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html),
[modifiers](https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html)
and [correlation](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
specifications using pySigma 1.5.1.

| Area | Remaining limitation |
| --- | --- |
| Multi-field value counts | A list in `condition.field` parses but is not supported by the correlation compiler. |
| Fractional aggregate thresholds | pySigma 1.5.1 converts condition thresholds to integers before the backend sees them. |
| Field existence | Flattened SQL NULL cannot distinguish a missing field from an explicitly null field; `exists` uses NULL tests. |
| String matching | Native SQLite case folding is ASCII; equality needs NOCASE columns or `collate_nocase=True`. LIKE/GLOB also have limitations for embedded NUL characters. |
| IPv6 ranges | CIDR prefix expansion depends on equivalent addresses using the same canonical spelling. |
| Timestamp parts | `%W` can return week zero; ordinary part extraction does not use the correlation `timestamp_format` option. |
| Regular expressions | A consumer must register REGEXP; its implementation determines regex compatibility. |

Encoding transformations, placeholder expansion, global filters and logsource
mapping are provided through pySigma and processing pipelines. The backend
implements the standard correlation families plus pySigma's median extension;
their presence does not remove the edge cases listed above.

## Corpus verification

The standard `rules/` tree at Sigma revision
`2e8fd89f82d9104c1b30321a307254ddeea17de2` converts and prepares with
`--fulltext-field _sigma_fulltext`:

| Profile | Converted and prepared | Keyword queries |
| --- | ---: | ---: |
| All standard rules, no pipeline | 3,144 | 86 |
| Windows Sysmon | 2,410 | 12 |
| Windows audit | 2,410 | 12 |
| Linux | 210 | 28 |

No parsing, conversion or preparation errors were recorded in these profiles.
This measures conversion coverage, not detection accuracy or logsource
applicability. Run the behavioral tests against real events as well.

```sh
poetry run python tools/audit_corpus.py /path/to/sigma \
  --fulltext-field _sigma_fulltext --profile raw --output corpus.json
SQLITE_MIN_BINARY=/path/to/sqlite-3.38 poetry run pytest -q
```

Windows audit profiles additionally require the Sysmon and Windows processing
pipeline packages. The corpus auditor provisions an empty, non-NULL TEXT column
to check SQL preparation; it does not invent matching source content.

## Behavioral and performance checks

The Sigma rule **Binary Padding - Linux** (`c52a914f-3d8b-4b2a-bb75-b3991e75f8ba`)
was exercised through Zircolite's CLI with five synthetic events. Only the two
expected events matched: `truncate` with `-s`, and `dd` with `if=` but without
`of=`. Arguments were nested arrays excluded from ordinary flattening. A benign
event remained unmatched despite a filename containing `truncate -s`. Saved
database reload produced the same results; detection and keepflat exports
omitted captured text.

A [reproducible synthetic benchmark](integrations/keyword-capture-benchmark.py)
ingests 100,000 JSONL events (54.54 MiB), then searches for one substring with
100 matches. Each event includes a 400-character payload, named fields and a
nested array. Measurements below are medians of three fresh processes on macOS
arm64, Python 3.14.7, SQLite 3.53.4, using Zircolite's Cython flattening backend
and an in-memory database:

| Measurement | Capture disabled | Capture enabled |
| --- | ---: | ---: |
| Ingestion | 0.514 s | 1.006 s |
| SQLite allocated pages | 49.79 MiB | 98.75 MiB |
| Process peak RSS | 143.05 MiB | 208.16 MiB |
| First keyword query, including validation | — | 71 ms |
| Keyword query with cached validation | — | 47 ms |

These numbers illustrate the cost of retaining and scanning values; they are
not throughput guarantees. The enabled runs retained 44.05 MiB of extra text.
Rules with different selectivity, larger events, regexes, disk databases or
different filtering behavior will have different costs. Capture stays disabled
when loaded rules do not need it.
