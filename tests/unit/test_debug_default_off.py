"""DEBUG must default to off.

DEBUG turns on SQLAlchemy echo (SQL with bound parameters in the logs) and the
public /docs routes. Production sets DEBUG=false, but the code default was True,
so dropping that env var would silently turn both on. herm-consumer-service
shipped exactly that to production.
"""

from app.core.config import Settings


def test_debug_defaults_to_off():
    assert Settings.model_fields["DEBUG"].default is False
