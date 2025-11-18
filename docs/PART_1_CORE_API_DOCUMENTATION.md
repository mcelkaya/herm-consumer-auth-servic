# Part 1: Core API Documentation

**Herm Authentication Service - Integration Guide**

---

## Table of Contents

1. [Overview](#overview)
2. [Environment Configuration](#environment-configuration)
3. [API Endpoints Reference](#api-endpoints-reference)
4. [Authentication Flow](#authentication-flow)
5. [Error Handling](#error-handling)

---

## Overview

The Herm Authentication Service is a FastAPI-based microservice that provides user authentication and OAuth email provider integration capabilities. It uses JWT (JSON Web Tokens) for stateless authentication and supports integration with Gmail, Outlook, and Yahoo email providers.

**Technology Stack:**
- Framework: FastAPI 0.115.0
- Database: PostgreSQL (async with SQLAlchemy)
- Authentication: JWT with HS256 algorithm
- Password Hashing: bcrypt
- API Documentation: OpenAPI/Swagger (available at `/docs`)

**Base URL Structure:**
```
{BASE_URL}/herm-auth/api/v1
```

---

## Environment Configuration

### Required Environment Variables

Create a `.env` file in the project root with the following variables:

#### Application Settings

```bash
# Application
APP_NAME=Email Integration Service
APP_VERSION=1.0.0
ENVIRONMENT=development  # Options: development, staging, production
DEBUG=true              # Set to false in production
```

#### Database Configuration

```bash
# Database - PostgreSQL with async support
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/email_integration
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10
```

**Note:** The `DATABASE_URL` must use `postgresql+asyncpg://` as the driver for async operations.

#### JWT Authentication Settings

```bash
# JWT Authentication
SECRET_KEY=your-secret-key-change-in-production  # CRITICAL: Use a strong secret in production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

**Security Requirements:**
- `SECRET_KEY`: Must be a cryptographically secure random string (minimum 32 characters recommended)
- Generate using: `openssl rand -hex 32`

#### OAuth Provider Configuration

```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/herm-auth/api/v1/oauth/google/callback

# Microsoft OAuth
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_REDIRECT_URI=http://localhost:8000/herm-auth/api/v1/oauth/microsoft/callback

# Yahoo OAuth
YAHOO_CLIENT_ID=your-yahoo-client-id
YAHOO_CLIENT_SECRET=your-yahoo-client-secret
YAHOO_REDIRECT_URI=http://localhost:8000/herm-auth/api/v1/oauth/yahoo/callback
```

#### Additional Services

```bash
# Redis - For caching and task queue
REDIS_URL=redis://localhost:6379/0

# AWS - For cloud services
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# Logging
LOG_LEVEL=INFO  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
```

### Base URLs by Environment

| Environment | Base URL |
|-------------|----------|
| Development | `http://localhost:8000` |
| Staging | `https://staging-api.yourdomain.com` |
| Production | `https://api.yourdomain.com` |

### CORS Configuration

**Current Settings** (from `app/main.py:15-22`):

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Currently allows all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Production Recommendation:**

Replace `allow_origins=["*"]` with specific allowed origins:

```python
allow_origins=[
    "https://yourdomain.com",
    "https://app.yourdomain.com",
    "https://staging.yourdomain.com"
]
```

---

## API Endpoints Reference

### Authentication Endpoints

All authentication endpoints are prefixed with `/herm-auth/api/v1/auth`

---

#### 1. Register / Signup

**Endpoint:** `POST /herm-auth/api/v1/auth/signup`

**Purpose:** Register a new user account and receive authentication tokens.

**Request Headers:**
```http
Content-Type: application/json
```

**Request Body Schema:**

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| email | string | Yes | Valid email format | User's email address |
| password | string | Yes | 8-100 characters | User's password |

**Request Body Example:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Success Response (201 Created):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Response Schema:**

| Field | Type | Description |
|-------|------|-------------|
| access_token | string | JWT access token (expires in 30 minutes by default) |
| refresh_token | string | JWT refresh token (expires in 7 days by default) |
| token_type | string | Always "bearer" |

**Error Responses:**

**400 Bad Request - Email Already Registered:**
```json
{
  "detail": "Email already registered"
}
```

**422 Unprocessable Entity - Validation Error:**
```json
{
  "detail": [
    {
      "type": "string_too_short",
      "loc": ["body", "password"],
      "msg": "String should have at least 8 characters",
      "input": "short",
      "ctx": {
        "min_length": 8
      }
    }
  ]
}
```

**Status Codes:**
- `201` - User successfully created
- `400` - Email already registered
- `422` - Validation error (invalid email format or password too short)
- `500` - Internal server error

**Implementation:** `app/api/v1/auth.py:12-24`

---

#### 2. Login

**Endpoint:** `POST /herm-auth/api/v1/auth/login`

**Purpose:** Authenticate an existing user and receive authentication tokens.

**Request Headers:**
```http
Content-Type: application/json
```

**Request Body Schema:**

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| email | string | Yes | Valid email format | User's email address |
| password | string | Yes | - | User's password |

**Request Body Example:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Success Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Error Responses:**

**401 Unauthorized - Invalid Credentials:**
```json
{
  "detail": "Incorrect email or password"
}
```

**403 Forbidden - Inactive Account:**
```json
{
  "detail": "User account is inactive"
}
```

**422 Unprocessable Entity - Validation Error:**
```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "email"],
      "msg": "value is not a valid email address",
      "input": "invalid-email"
    }
  ]
}
```

**Status Codes:**
- `200` - Successfully authenticated
- `401` - Invalid email or password
- `403` - User account is inactive
- `422` - Validation error
- `500` - Internal server error

**Implementation:** `app/api/v1/auth.py:27-39`

**Security Notes:**
- Password is verified using bcrypt hashing
- Passwords are truncated to 72 bytes for bcrypt compatibility
- Returns generic error message for both invalid email and password (prevents user enumeration)

---

#### 3. Get Current User

**Endpoint:** `GET /herm-auth/api/v1/auth/me`

**Purpose:** Retrieve the authenticated user's profile information.

**Request Headers:**
```http
Authorization: Bearer <access_token>
```

**Request Body:** None

**cURL Example:**
```bash
curl -X GET "http://localhost:8000/herm-auth/api/v1/auth/me" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Success Response (200 OK):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "is_active": true,
  "is_verified": false,
  "created_at": "2025-11-18T10:30:00.000000"
}
```

**Response Schema:**

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | User's unique identifier |
| email | string | User's email address |
| is_active | boolean | Whether the account is active |
| is_verified | boolean | Whether the email is verified |
| created_at | datetime | Account creation timestamp (ISO 8601 format) |

**Error Responses:**

**401 Unauthorized - Missing or Invalid Token:**
```json
{
  "detail": "Not authenticated"
}
```

**401 Unauthorized - Expired or Invalid JWT:**
```json
{
  "detail": "Could not validate credentials"
}
```

**403 Forbidden - Inactive Account:**
```json
{
  "detail": "User account is inactive"
}
```

**404 Not Found - User Deleted:**
```json
{
  "detail": "User not found"
}
```

**Status Codes:**
- `200` - Successfully retrieved user information
- `401` - Missing, invalid, or expired token
- `403` - User account is inactive
- `404` - User not found
- `500` - Internal server error

**Implementation:** `app/api/v1/auth.py:42-49`

**Authentication Flow:**
1. Extract Bearer token from Authorization header
2. Decode and verify JWT signature
3. Extract user ID from token payload (`sub` claim)
4. Fetch user from database
5. Verify user is active
6. Return user information

**JWT Token Payload Structure:**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "exp": 1700308200,
  "type": "access"
}
```

---

#### 4. Token Refresh

**Status:** ⚠️ **NOT IMPLEMENTED**

This endpoint is not currently available in the codebase. The service issues refresh tokens during login/signup, but there is no endpoint to exchange a refresh token for a new access token.

**Expected Implementation:**
```
POST /herm-auth/api/v1/auth/refresh
```

**Recommendation:** Implement this endpoint to allow clients to obtain new access tokens without re-authenticating. Expected behavior:
- Accept refresh token in request body
- Validate refresh token (verify signature, expiration, and type claim)
- Issue new access token
- Optionally issue new refresh token (token rotation)

---

#### 5. Password Reset

**Status:** ⚠️ **NOT IMPLEMENTED**

Password reset functionality is not currently available in the codebase.

**Expected Implementation:**
```
POST /herm-auth/api/v1/auth/password-reset-request
POST /herm-auth/api/v1/auth/password-reset-confirm
```

**Recommendation:** Implement a secure password reset flow:
1. User requests reset with email address
2. System sends reset token/link via email
3. User submits new password with reset token
4. System validates token and updates password

---

#### 6. Email Verification

**Status:** ⚠️ **NOT IMPLEMENTED**

Email verification functionality is not currently available in the codebase. The `User` model includes an `is_verified` field, but there are no endpoints to verify emails.

**Expected Implementation:**
```
POST /herm-auth/api/v1/auth/send-verification-email
POST /herm-auth/api/v1/auth/verify-email
```

**Recommendation:** Implement email verification:
1. Send verification email after signup
2. User clicks verification link with token
3. System validates token and sets `is_verified=True`

---

#### 7. Update User

**Status:** ⚠️ **NOT IMPLEMENTED**

User profile update functionality is not currently available via API endpoints.

**Expected Implementation:**
```
PATCH /herm-auth/api/v1/auth/me
PUT /herm-auth/api/v1/auth/password
```

**Recommendation:** Implement user update endpoints:
- Update email address (with re-verification)
- Change password (requires current password)
- Update profile fields
- Deactivate account

---

### Health Check Endpoint

#### Health Check

**Endpoint:** `GET /herm-auth/health`

**Purpose:** Verify service availability and version.

**Request Headers:** None required

**Success Response (200 OK):**

```json
{
  "status": "healthy",
  "service": "Email Integration Service",
  "version": "1.0.0"
}
```

**Implementation:** `app/main.py:26-33`

---

## Authentication Flow

### JWT Authentication Mechanism

This service uses **Bearer Token Authentication** with JWT tokens.

#### Token Types

| Token Type | Expiration | Usage | Claim `type` |
|------------|------------|-------|--------------|
| Access Token | 30 minutes (default) | API authentication | `"access"` |
| Refresh Token | 7 days (default) | Token renewal | `"refresh"` |

#### Access Token Structure

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "exp": 1700308200,
  "type": "access"
}
```

**Claims:**
- `sub` (Subject): User's UUID
- `email`: User's email address
- `exp` (Expiration): Unix timestamp
- `type`: Token type (`"access"` or `"refresh"`)

#### Refresh Token Structure

**Payload:**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1700913000,
  "type": "refresh"
}
```

**Note:** Refresh tokens do not include the email claim.

#### How to Use Authentication

**1. Register or Login:**

```bash
curl -X POST "http://localhost:8000/herm-auth/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "bearer"
}
```

**2. Make Authenticated Requests:**

Include the access token in the `Authorization` header:

```bash
curl -X GET "http://localhost:8000/herm-auth/api/v1/auth/me" \
  -H "Authorization: Bearer eyJhbGc..."
```

**3. Token Storage (Client-Side):**

- **Access Token:** Store in memory or short-lived storage (session storage)
- **Refresh Token:** Store securely (httpOnly cookie recommended for web apps)
- Never store tokens in localStorage if handling sensitive data

**4. Token Expiration Handling:**

When you receive a `401 Unauthorized` response:
- Check if access token is expired
- Use refresh token to get new access token (when refresh endpoint is implemented)
- If refresh token is expired, redirect to login

#### Password Security

**Implementation:** `app/core/security.py:14-35`

- **Hashing Algorithm:** bcrypt
- **Password Truncation:** Passwords are truncated to 72 bytes for bcrypt compatibility
- **Validation:** Minimum 8 characters, maximum 100 characters

---

## Error Handling

### Standard Error Response Format

All errors follow FastAPI's standard error format:

```json
{
  "detail": "Error message describing what went wrong"
}
```

### HTTP Status Codes

| Status Code | Meaning | When Used |
|-------------|---------|-----------|
| 200 | OK | Successful request |
| 201 | Created | Resource successfully created (signup) |
| 400 | Bad Request | Business logic error (e.g., email already registered) |
| 401 | Unauthorized | Authentication failed or missing |
| 403 | Forbidden | Authenticated but not authorized (e.g., inactive account) |
| 404 | Not Found | Resource not found |
| 422 | Unprocessable Entity | Request validation failed |
| 500 | Internal Server Error | Unexpected server error |

### Common Error Scenarios

#### Validation Errors (422)

Pydantic validation errors return detailed information:

```json
{
  "detail": [
    {
      "type": "string_too_short",
      "loc": ["body", "password"],
      "msg": "String should have at least 8 characters",
      "input": "short",
      "ctx": {
        "min_length": 8
      }
    }
  ]
}
```

**Fields:**
- `type`: Error type
- `loc`: Location of error (e.g., `["body", "field_name"]`)
- `msg`: Human-readable error message
- `input`: The invalid input value
- `ctx`: Additional context

#### Authentication Errors (401)

```json
{
  "detail": "Could not validate credentials"
}
```

Common causes:
- Missing Authorization header
- Invalid JWT token
- Expired JWT token
- Invalid JWT signature

#### Authorization Errors (403)

```json
{
  "detail": "User account is inactive"
}
```

#### Business Logic Errors (400)

```json
{
  "detail": "Email already registered"
}
```

### Global Exception Handler

**Implementation:** `app/main.py:43-49`

All unhandled exceptions are caught and returned as:

```json
{
  "detail": "Internal server error"
}
```

**Note:** In production, detailed error messages are hidden to prevent information leakage. Check server logs for detailed error information.

---

## API Testing Tools

### Interactive API Documentation

FastAPI provides auto-generated interactive documentation:

- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`

### Example: Complete Authentication Flow

```bash
# 1. Register a new user
curl -X POST "http://localhost:8000/herm-auth/api/v1/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "password": "SecurePassword123!"
  }'

# Response:
# {
#   "access_token": "eyJhbGc...",
#   "refresh_token": "eyJhbGc...",
#   "token_type": "bearer"
# }

# 2. Get current user information (using the access token from step 1)
curl -X GET "http://localhost:8000/herm-auth/api/v1/auth/me" \
  -H "Authorization: Bearer eyJhbGc..."

# Response:
# {
#   "id": "550e8400-e29b-41d4-a716-446655440000",
#   "email": "newuser@example.com",
#   "is_active": true,
#   "is_verified": false,
#   "created_at": "2025-11-18T10:30:00.000000"
# }
```

---

## Next Steps

This document covers the core authentication API. For additional functionality, see:

- **Part 2:** OAuth Integration Guide (Google, Microsoft, Yahoo)
- **Part 3:** Connected Apps Management
- **Part 4:** Security Best Practices
- **Part 5:** Deployment and Monitoring

---

**Document Version:** 1.0
**Last Updated:** 2025-11-18
**Service Version:** 1.0.0
