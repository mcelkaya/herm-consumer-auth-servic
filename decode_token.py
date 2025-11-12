#!/usr/bin/env python
"""Decode JWT token and extract user information"""
import jwt
import json
from datetime import datetime

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI4OTVlNjc3OS1mMjU5LTRmZmYtODkxNy0yM2Y2YjlkMDY1OTUiLCJlbWFpbCI6InRlc3QyQGV4YW1wbGUuY29tIiwiZXhwIjoxNzYyOTQ4NTQwLCJ0eXBlIjoiYWNjZXNzIn0.zrWmLUevJMqCjTXUhaodyDwxJw2xPt0J8SHgxmkkyVQ"

print("=" * 60)
print("JWT TOKEN DECODED")
print("=" * 60)

# Decode without verification to see payload
decoded = jwt.decode(token, options={"verify_signature": False})

print("\n📋 Token Payload:")
print(json.dumps(decoded, indent=2))

print("\n👤 User Information:")
print(f"  User ID (sub): {decoded.get('sub')}")
print(f"  Email: {decoded.get('email')}")
print(f"  Token Type: {decoded.get('type')}")

# Convert expiration to readable format
exp_timestamp = decoded.get("exp")
if exp_timestamp:
    exp_date = datetime.fromtimestamp(exp_timestamp)
    print(f"  Expires At: {exp_date.strftime('%Y-%m-%d %H:%M:%S')}")

    # Check if expired
    now = datetime.now()
    if exp_date > now:
        days_left = (exp_date - now).days
        print(f"  Status: ✓ Valid (expires in {days_left} days)")
    else:
        print(f"  Status: ✗ Expired")

print("\n" + "=" * 60)

