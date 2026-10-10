# Zircolite keyword-search integration

The [companion patch](zircolite-keyword-search.patch) adds keyword capture and
execution to Zircolite. It is based on Zircolite commit `f384318` and accompanies
this backend's `feat/sigma-keyword-search` branch. The consumer commit is
`e48daa335efb0c3e65ff40a117b16143e004fee2`. Apply it to a clean checkout
based on that commit; a checkout with later or local changes may need conflict
resolution.

The implementation was developed on the same branch name in an isolated clone.
The original sibling Zircolite checkout, which contained unrelated local edits,
was left untouched. Neither repository's branch was pushed or merged.

## Apply and install

In a separate Zircolite checkout:

```sh
git switch -c feat/sigma-keyword-search f384318
git apply --check /path/to/pySigma-backend-sqlite/docs/integrations/zircolite-keyword-search.patch
git apply /path/to/pySigma-backend-sqlite/docs/integrations/zircolite-keyword-search.patch
```

Build this backend with `poetry build`. Install its wheel into the Python
environment that runs the patched Zircolite, then install that Zircolite
checkout normally. For a pip-managed virtual environment:

```sh
python -m pip install --no-deps --force-reinstall /path/to/pySigma-backend-sqlite/dist/pysigma_backend_sqlite-2.0.0-py3-none-any.whl
python -m pip install --no-deps -e /path/to/patched/Zircolite
```

These are coordinated development changes. Package versions have not been
bumped; the wheel must come from this branch. An older published backend does
not provide this feature even if it has the same version number. Release
versions and dependency floors must be updated together when publishing.

## Behavior

YAML conversion configures `_sigma_fulltext` automatically. Loading a ruleset
with keyword prerequisites enables source-value capture before flattening, for
sequential, unified and worker processing. Databases saved from that run contain
both the text column and `_zircolite_fulltext` provenance. The private text is
omitted from matches, correlation evidence, CSV and keepflat exports.

Re-ingest source events to use keyword rules with older databases. A missing,
incomplete or incompatible text representation is reported as a rule error;
independent rules remain executable. Captured databases retain values that
ordinary field exclusions would otherwise discard.

For library use, load the rules before `run_streaming`, or pass
`ProcessingConfig(fulltext_capture=True)` to `ZircoliteCore` or
`StreamingEventProcessor`. See the [backend contract and validation results](../keyword-search.md)
for representation details, Sigma compatibility gaps and measured costs.

## Reproduce the benchmark

With both changes installed in the active Python environment:

```sh
python keyword-capture-benchmark.py prepare /tmp/keyword-benchmark
python keyword-capture-benchmark.py off /tmp/keyword-benchmark
python keyword-capture-benchmark.py on /tmp/keyword-benchmark
```

Run `off` and `on` three times each in separate processes. The script lives next
to this document and writes only synthetic input files to the chosen directory.
Its RSS measurement uses the macOS byte convention for `ru_maxrss`; Linux
reports KiB instead, so multiply that field by 1,024 to compare byte values.

## Validation

- Backend: 204 tests passed, including execution with the SQLite 3.38.0 CLI;
  wheel and source distribution builds passed.
- Consumer: 24 feature tests passed, including Python/Cython flattening and
  sequential, unified, thread and process execution. The final focused core,
  correlation and keyword suites passed all 186 tests.
- The consumer full suite recorded 2,519 passed, 44 skipped and two failures.
  Both failures reproduced before this change:
  `tests/test_tools.py::TestSigmaRegressionUntrustedText::test_failed_rule_title_with_markup`
  and `test_missing_data_file_path_with_markup`. Their captured console text
  wraps differently from the literal-string assertions. Subsequent
  collision, provenance and validation-cache fixes were checked by the focused suites above.
- Consumer Ruff and mypy passed. The companion patch passed `git apply --check`
  against a clean archive of `f384318`.
- A real Sigma Linux rule passed ingestion, detection, saved-database reload
  and export checks; the [coverage and costs](../keyword-search.md) document
  contains the corpus totals and benchmark conditions.
