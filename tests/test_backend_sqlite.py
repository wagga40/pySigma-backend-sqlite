import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend


@pytest.fixture
def sqlite_backend():
    return sqliteBackend()


# TODO: implement tests for some basic queries and their expected results.
def test_sqlite_and_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' AND fieldB='valueB'"]
    )


def test_sqlite_or_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldB='valueB'"]
    )


def test_sqlite_and_or_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' OR fieldA='valueA2') AND (fieldB='valueB1' OR fieldB='valueB2')"
        ]
    )


def test_sqlite_or_and_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' AND fieldB='valueB1') OR (fieldA='valueA2' AND fieldB='valueB2')"
        ]
    )


def test_sqlite_in_expression(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldA='valueB' OR fieldA LIKE 'valueC%' ESCAPE '\\'"
        ]
    )


def test_sqlite_regex_query(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA REGEXP 'foo.*bar' AND fieldB='foo'"
        ]
    )


def test_sqlite_cidr_query(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE field LIKE '192.168.%' ESCAPE '\\'"]
    )


def test_sqlite_field_name_with_whitespace(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE `field name`='value'"]
    )


def test_sqlite_value_with_wildcards(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: wildcard%value
                    fieldB: wildcard_value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE 'wildcard\\%value' ESCAPE '\\' AND fieldB LIKE 'wildcard\\_value' ESCAPE '\\'"
        ]
    )


def test_sqlite_value_contains(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE '%wildcard\\%value%' ESCAPE '\\'"
        ]
    )


def test_sqlite_value_startswith(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE 'wildcard\\%value%' ESCAPE '\\'"
        ]
    )


def test_sqlite_value_endswith(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: wildcard%value
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA LIKE '%wildcard\\%value' ESCAPE '\\'"
        ]
    )


def test_sqlite_fts_keywords_str(sqlite_backend: sqliteBackend):
    with pytest.raises(Exception) as e:
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - value1
                    - value2
                condition: keywords
        """
            )
        )
    assert (
        str(e.value)
        == "Value-only string expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
    )


def test_sqlite_fts_keywords_num(sqlite_backend: sqliteBackend):
    with pytest.raises(Exception) as e:
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 1
                    - 2
                condition: keywords
        """
            )
        )
    assert (
        str(e.value)
        == "Value-only number expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
    )

def test_sqlite_value_case_sensitive_contains(sqlite_backend: sqliteBackend):
    assert (
        sqlite_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains|cased: VaLuE
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA GLOB '*VaLuE*' ESCAPE '\\'"
        ]
    )

def test_sqlite_zircolite_output(sqlite_backend: sqliteBackend):
    rule = SigmaCollection.from_yaml(
        r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value
                condition: sel
        """
    )
    assert (
        sqlite_backend.convert(rule, "zircolite")
        == '[{"title": "Test", "id": "", "status": "test", "description": "", "author": "", "tags": [], "falsepositives": [], "level": "", "rule": ["SELECT * FROM logs WHERE fieldA=\'value\'"], "filename": ""}]'
    )


# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.
