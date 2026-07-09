"""Guard against tests/conftest.py silently pointing the test suite at the
real dev database.

Regression: TEST_DATABASE_URL was derived via
DATABASE_URL.replace("/email_integration", "/test_email_integration"), which
assumed the dev DB was literally named "email_integration". Once DATABASE_URL
moved to the shared multi-schema "hermio" database, that replace became a
silent no-op, so tests ran (and did Base.metadata.create_all/drop_all)
directly against the real dev database, wiping herm_auth's tables on every
test run.
"""

from tests.conftest import TEST_DATABASE_URL
from app.core.config import settings


def test_test_database_is_not_the_dev_database():
    assert TEST_DATABASE_URL != settings.DATABASE_URL, (
        "TEST_DATABASE_URL resolved to the same URL as the dev DATABASE_URL "
        "- the test suite would run create_all/drop_all against the real "
        "dev database."
    )
