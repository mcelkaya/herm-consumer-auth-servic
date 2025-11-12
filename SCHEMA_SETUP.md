# Database Schema Configuration

## Overview
This project now supports separate database schemas through the `DATABASE_SCHEMA` environment variable. This allows you to organize your database tables into different schemas for better separation and organization.

## Changes Made

### 1. Environment Configuration (.env)
Added `DATABASE_SCHEMA` variable:
```env
DATABASE_SCHEMA=public
```

You can change this to any schema name you want (e.g., `auth_service`, `email_integration`, etc.).

### 2. Application Configuration (app/core/config.py)
Added `DATABASE_SCHEMA` setting to the Settings class:
```python
DATABASE_SCHEMA: str = "public"
```

### 3. Database Models
Updated both models to use the schema configuration:

**app/models/user.py**
- Added import for `settings`
- Added `__table_args__ = {"schema": settings.DATABASE_SCHEMA}`

**app/models/connected_app.py**
- Added import for `settings`
- Added `__table_args__ = {"schema": settings.DATABASE_SCHEMA}`
- Updated foreign key reference to include schema: `f"{settings.DATABASE_SCHEMA}.users.id"`

### 4. Alembic Configuration
Updated migration configuration to support schemas:

**alembic/env.py**
- Added `version_table_schema=settings.DATABASE_SCHEMA` to both offline and online migration functions
- This ensures Alembic's version tracking table is created in the correct schema

**alembic/versions/001_initial_migration.py**
- Added schema creation logic (creates schema if it doesn't exist and it's not 'public')
- Added `schema=settings.DATABASE_SCHEMA` parameter to all table creation and index operations
- Updated foreign key references to include schema
- Added schema cleanup in downgrade function

## Usage

### To Use a Custom Schema

1. Update your `.env` file:
   ```env
   DATABASE_SCHEMA=my_custom_schema
   ```

2. Run migrations:
   ```bash
   alembic upgrade head
   ```

3. The schema will be automatically created if it doesn't exist (unless using 'public')

### To Use the Default 'public' Schema

Simply leave the default value or set:
```env
DATABASE_SCHEMA=public
```

## Important Notes

- If you change the schema name after running migrations, you'll need to either:
  - Run `alembic downgrade base` to remove old tables, then `alembic upgrade head` with the new schema
  - Manually migrate your data to the new schema
  
- The schema name is loaded at application startup, so restart your application after changing it

- Make sure the PostgreSQL user has permissions to create schemas if using a custom schema name

## Testing

To verify the schema configuration is working:

1. Check that tables are created in the correct schema:
   ```sql
   SELECT table_schema, table_name 
   FROM information_schema.tables 
   WHERE table_schema = 'your_schema_name';
   ```

2. Verify Alembic version table location:
   ```sql
   SELECT * FROM your_schema_name.alembic_version;
   ```

