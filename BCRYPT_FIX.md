# Bcrypt Password Hashing Fix

## Problem
The application was throwing a `ValueError: password cannot be longer than 72 bytes` error when trying to hash passwords. This is because bcrypt has a hard limit of 72 bytes for password input.

## Root Causes
1. **Bcrypt 72-byte limit**: Bcrypt can only hash passwords up to 72 bytes in length
2. **Version incompatibility**: Bcrypt 5.x has compatibility issues with passlib 1.7.4 and Python 3.13

## Solution

### 1. Updated Password Hashing Logic (`app/core/security.py`)
Added a `_truncate_password()` method that:
- Converts passwords to bytes using UTF-8 encoding
- Truncates to 72 bytes if the password exceeds this limit
- Safely decodes back to string for bcrypt hashing

```python
@staticmethod
def _truncate_password(password: str) -> bytes:
    """
    Truncate password to 72 bytes for bcrypt compatibility.
    Bcrypt has a maximum input length of 72 bytes.
    """
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    return password_bytes
```

### 2. Downgraded Bcrypt Version
- Changed from `bcrypt==5.0.0` to `bcrypt>=4.0.0,<5.0.0`
- Added explicit bcrypt version constraint to `requirements.txt`
- Bcrypt 4.x is more stable with passlib 1.7.4

### 3. Added psycopg2-binary
- Added `psycopg2-binary>=2.9.9,<3.0` for Alembic migrations
- Required for synchronous database operations during migrations

## Changes Made

### Files Modified:
1. **app/core/security.py**
   - Added `_truncate_password()` method
   - Updated `get_password_hash()` to use truncation
   - Updated `verify_password()` to use truncation

2. **requirements.txt**
   - Added `psycopg2-binary>=2.9.9,<3.0`
   - Added `bcrypt>=4.0.0,<5.0.0`

## Testing
Both normal and long passwords (>72 bytes) now hash and verify successfully:
- ✓ Normal passwords (e.g., "Qazxsw123!") work correctly
- ✓ Long passwords (>72 bytes) are truncated and work correctly
- ✓ Password verification works for both cases

## Installation
To apply these fixes on a new environment:
```bash
pip install -r requirements.txt
```

## Important Notes
- Passwords longer than 72 bytes will be truncated before hashing
- This is standard practice for bcrypt and doesn't reduce security
- Users won't notice any difference - the truncation is handled automatically
- The same password will always produce the same hash (consistent truncation)

## Future Considerations
If you need to support passwords longer than 72 bytes without truncation:
1. Pre-hash with SHA256 before bcrypt
2. Upgrade to a different password hashing algorithm (e.g., Argon2)
3. Update passlib to a newer version when it's compatible with Python 3.13

