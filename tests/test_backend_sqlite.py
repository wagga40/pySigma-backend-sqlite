import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

@pytest.fixture
def sqlite_backend():
    return sqliteBackend()

# TODO: implement tests for some basic queries and their expected results.
def test_sqlite_and_expression(sqlite_backend : sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' AND fieldB='valueB'"]

def test_sqlite_or_expression(sqlite_backend : sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldB='valueB'"]

def test_sqlite_and_or_expression(sqlite_backend : sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ["SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' OR fieldA='valueA2') AND (fieldB='valueB1' OR fieldB='valueB2')"]

def test_sqlite_or_and_expression(sqlite_backend : sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ["SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' AND fieldB='valueB1') OR (fieldA='valueA2' AND fieldB='valueB2')"]

def test_sqlite_in_expression(sqlite_backend : sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldA='valueB' OR fieldA LIKE 'valueC%'"]

def test_sqlite_regex_query(sqlite_backend : sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml("""
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
        """)
    ) == ["SELECT * FROM <TABLE_NAME> WHERE fieldA REGEXP 'foo.*bar' AND fieldB='foo'"]

def test_sqlite_cidr_query(sqlite_backend : sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ["SELECT * FROM <TABLE_NAME> WHERE field='192.168.\%'"]

def test_sqlite_field_name_with_whitespace(sqlite_backend : sqliteBackend):
    assert sqlite_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ["SELECT * FROM <TABLE_NAME> WHERE `field name`='value'"]

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.


