#!/usr/bin/env python
"""Run alembic migrations with error handling"""
import sys
from alembic.config import Config
from alembic import command

try:
    print("=" * 60)
    print("Running Alembic Migrations")
    print("=" * 60)

    # Create alembic config
    alembic_cfg = Config("alembic.ini")

    # Show current version
    print("\nCurrent migration version:")
    try:
        command.current(alembic_cfg, verbose=True)
    except Exception as e:
        print(f"  Could not determine current version: {e}")

    # Run upgrade
    print("\nUpgrading to head...")
    command.upgrade(alembic_cfg, "head", sql=False)

    # Show new version
    print("\nNew migration version:")
    command.current(alembic_cfg, verbose=True)

    print("\n" + "=" * 60)
    print("✓ Migrations completed successfully")
    print("=" * 60)

except Exception as e:
    print(f"\n✗ Error running migrations: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

