# Part 2: Authentication Flows & Token Management

**Herm Authentication Service - Integration Guide**

---

## Table of Contents

1. [Authentication System Overview](#authentication-system-overview)
2. [Step-by-Step Authentication Flows](#step-by-step-authentication-flows)
3. [Token Management Details](#token-management-details)
4. [Error Handling](#error-handling)
5. [Best Practices](#best-practices)

---

## Authentication System Overview

### Authentication Type

The Herm Authentication Service uses **JWT (JSON Web Token) authentication** with a Bearer token scheme. This is a stateless authentication mechanism where tokens are cryptographically signed and can be verified without database lookups.

**Key Characteristics:**
- **Stateless:** Server doesn't maintain session state
- **Self-contained:** Tokens carry user identity and claims
- **Cryptographically signed:** Prevents token tampering
- **Time-limited:** Tokens expire automatically

### Architecture Summary

```
┌─────────────┐                    ┌─────────────────┐
│   Client    │                    │  Auth Service   │
│             │                    │                 │
│             │  1. Login/Signup   │                 │
│             │ ────────────────>  │                 │
│             │  (email+password)  │                 │
│             │                    │  2. Validate    │
│             │                    │     credentials │
│             │                    │                 │
│             │  3. Return Tokens  │  3. Generate    │
│             │ <────────────────  │     JWT tokens  │
│             │  (access+refresh)  │                 │
│             │                    │                 │
│ 4. Store    │                    │                 │
│    tokens   │                    │                 │
│             │                    │                 │
│             │  5. API Request    │                 │
│             │ ────────────────>  │                 │
│             │  Authorization:    │  6. Verify JWT  │
│             │  Bearer <token>    │     signature   │
│             │                    │                 │
│             │  7. Response       │                 │
│             │ <────────────────  │                 │
└─────────────┘                    └─────────────────┘
```

### Core Components

**Implementation Files:**

| Component | File | Purpose |
|-----------|------|---------|
| JWT Operations | `app/core/security.py` | Token creation, signing, and verification |
| Password Security | `app/core/security.py` | bcrypt hashing and validation |
| Configuration | `app/core/config.py` | Token expiration settings, secret keys |
| Auth Endpoints | `app/api/v1/auth.py` | Login, signup, user info endpoints |
| Auth Dependencies | `app/api/dependencies.py` | Token extraction and validation middleware |
| Business Logic | `app/services/user_service.py` | User authentication and management |

### Security Features

**Implemented:**
- ✅ JWT token signing with HS256 (HMAC SHA-256)
- ✅ bcrypt password hashing
- ✅ Password truncation for bcrypt compatibility (72 bytes)
- ✅ Token expiration enforcement
- ✅ User account activation status checking
- ✅ Protection against user enumeration (generic error messages)

**Not Implemented:**
- ⚠️ Token refresh mechanism (refresh tokens are issued but cannot be used)
- ⚠️ Server-side token revocation/blacklisting
- ⚠️ Token rotation on refresh
- ⚠️ Rate limiting on authentication endpoints
- ⚠️ Account lockout after failed login attempts

---

## Step-by-Step Authentication Flows

### 1. Login Flow

**Objective:** Authenticate existing user and obtain access + refresh tokens.

#### Step-by-Step Process

**Step 1: Client Sends Credentials**

```http
POST /herm-auth/api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Step 2: Server Validates Credentials**

*Implementation: `app/services/user_service.py:48-83`*

1. **Database Lookup** (line 51):
   - Query user table by email
   - If not found → return 401 "Incorrect email or password"

2. **Password Verification** (lines 59-63):
   - Extract password hash from user record
   - Compare submitted password with stored hash using bcrypt
   - If mismatch → return 401 "Incorrect email or password"

3. **Account Status Check** (lines 66-70):
   - Verify `user.is_active == True`
   - If inactive → return 403 "User account is inactive"

**Step 3: Server Generates Tokens**

*Implementation: `app/core/security.py:38-64`*

**Access Token Generation** (lines 38-53):
```python
# Payload
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",  # User ID
  "email": "user@example.com",
  "exp": 1700308200,  # Current time + 30 minutes
  "type": "access"
}
```

**Refresh Token Generation** (lines 56-64):
```python
# Payload
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",  # User ID
  "exp": 1700913000,  # Current time + 7 days
  "type": "refresh"
}
```

**Step 4: Server Returns Tokens**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJleHAiOjE3MDAzMDgyMDAsInR5cGUiOiJhY2Nlc3MifQ.signature",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJleHAiOjE3MDA5MTMwMDAsInR5cGUiOiJyZWZyZXNoIn0.signature",
  "token_type": "bearer"
}
```

**Step 5: Client Stores Tokens**

**Recommended Storage Strategy:**

| Token Type | Storage Location | Reason |
|------------|------------------|--------|
| Access Token | Memory or sessionStorage | Short-lived, frequent access needed |
| Refresh Token | httpOnly cookie or secure storage | Long-lived, needs protection from XSS |

**Security Notes:**
- **Never** store tokens in localStorage for sensitive applications (XSS risk)
- Use httpOnly cookies when possible (not accessible to JavaScript)
- Clear tokens on logout
- Implement token refresh before access token expires

#### Complete Login Example

**JavaScript/Fetch:**
```javascript
async function login(email, password) {
  try {
    const response = await fetch('http://localhost:8000/herm-auth/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail);
    }

    const { access_token, refresh_token, token_type } = await response.json();

    // Store tokens
    sessionStorage.setItem('access_token', access_token);
    // Store refresh token in httpOnly cookie (server-side) or secure storage

    return { access_token, refresh_token };
  } catch (error) {
    console.error('Login failed:', error.message);
    throw error;
  }
}
```

**cURL:**
```bash
curl -X POST "http://localhost:8000/herm-auth/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Python:**
```python
import requests

def login(email: str, password: str) -> dict:
    url = "http://localhost:8000/herm-auth/api/v1/auth/login"
    payload = {"email": email, "password": password}

    response = requests.post(url, json=payload)
    response.raise_for_status()

    return response.json()

# Usage
tokens = login("user@example.com", "SecurePassword123!")
access_token = tokens["access_token"]
refresh_token = tokens["refresh_token"]
```

---

### 2. Token Refresh Flow

**Status:** ⚠️ **NOT CURRENTLY IMPLEMENTED**

**Current Limitation:** The service generates and returns refresh tokens during login/signup, but there is **no endpoint** to exchange a refresh token for a new access token. This is a critical gap in the authentication system.

#### How Token Refresh Should Work

**Objective:** Obtain a new access token using a valid refresh token without re-authenticating.

**Expected Implementation:**

**Step 1: Detect Access Token Expiration**

```javascript
// When API returns 401 due to expired access token
if (response.status === 401) {
  const errorData = await response.json();
  if (errorData.detail === "Could not validate credentials") {
    // Token might be expired, attempt refresh
    await refreshAccessToken();
  }
}
```

**Step 2: Request New Access Token (Expected Endpoint)**

```http
POST /herm-auth/api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Step 3: Server Validates Refresh Token (Expected Behavior)**

1. Decode refresh token
2. Verify signature
3. Check expiration (`exp` claim)
4. Verify `type` claim is `"refresh"`
5. Verify user still exists and is active
6. Generate new access token (and optionally new refresh token)

**Step 4: Server Returns New Tokens (Expected Response)**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Optionally with token rotation:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

#### Workaround for Current Implementation

**Since refresh is not implemented, clients must:**

1. **Monitor Access Token Expiration:**
   - Decode JWT on client side (or track issue time)
   - Calculate time until expiration
   - Prompt user to re-login before expiration

2. **Graceful Re-authentication:**
   ```javascript
   function isTokenExpiringSoon(token, bufferMinutes = 5) {
     const payload = JSON.parse(atob(token.split('.')[1]));
     const expirationTime = payload.exp * 1000; // Convert to milliseconds
     const bufferTime = bufferMinutes * 60 * 1000;
     return Date.now() > (expirationTime - bufferTime);
   }

   // Check before making requests
   if (isTokenExpiringSoon(accessToken)) {
     // Redirect to login or show re-authentication dialog
     redirectToLogin();
   }
   ```

3. **Handle 401 Errors:**
   ```javascript
   async function apiRequest(url, options) {
     const response = await fetch(url, options);

     if (response.status === 401) {
       // Access token expired, redirect to login
       redirectToLogin();
       throw new Error('Session expired, please log in again');
     }

     return response;
   }
   ```

**Recommendation:** Implement the refresh endpoint to improve user experience and security. See `app/core/security.py:56-64` for refresh token generation logic that can be extended to create a refresh endpoint.

---

### 3. Logout Flow

**Status:** ⚠️ **NOT CURRENTLY IMPLEMENTED**

**Current Limitation:** There is no server-side logout endpoint or token revocation mechanism. The service uses stateless JWT authentication, which means tokens cannot be invalidated server-side once issued.

#### How Logout Currently Works

**Client-Side Logout Only:**

Since tokens are stateless and cannot be revoked server-side, logout must be handled entirely on the client:

**Step 1: Clear Stored Tokens**

```javascript
function logout() {
  // Remove access token
  sessionStorage.removeItem('access_token');

  // Remove refresh token (if stored in localStorage)
  localStorage.removeItem('refresh_token');

  // Clear any user data
  sessionStorage.clear();

  // Redirect to login page
  window.location.href = '/login';
}
```

**Step 2: Stop Using Tokens**

- Remove Authorization header from API requests
- Clear any in-memory token references
- Clear application state

**Important Security Note:**

⚠️ **Tokens remain valid until expiration** even after client-side logout. If a token is stolen before logout, the attacker can use it until it expires.

**Implications:**
- Access tokens remain valid for up to 30 minutes after logout
- Refresh tokens remain valid for up to 7 days after logout
- No way to immediately invalidate compromised tokens

#### How Logout Should Work (Recommended Implementation)

**Expected Endpoint:**

```http
POST /herm-auth/api/v1/auth/logout
Authorization: Bearer <access_token>
```

**Server-Side Token Blacklisting:**

1. **Token Blacklist Storage:**
   - Maintain a blacklist of revoked tokens in Redis or database
   - Store token JTI (JWT ID) or signature with expiration time
   - Automatically remove expired tokens from blacklist

2. **Validation Check:**
   - On every authenticated request, check if token is blacklisted
   - If blacklisted, return 401 Unauthorized

**Example Implementation Pattern:**

```python
# Pseudocode for recommended implementation

@router.post("/logout")
async def logout(token: str = Depends(get_token)):
    # Decode token to get expiration
    payload = decode_token(token)
    expiration = payload.get("exp")

    # Add token to blacklist (Redis recommended)
    await redis.setex(
        f"blacklist:{token}",
        expiration - current_time,
        "revoked"
    )

    return {"message": "Successfully logged out"}

# In token validation
async def validate_token(token: str):
    # Check if token is blacklisted
    is_blacklisted = await redis.exists(f"blacklist:{token}")
    if is_blacklisted:
        raise HTTPException(status_code=401, detail="Token has been revoked")

    # Continue with normal validation
    ...
```

#### Complete Logout Example (Client-Side)

**JavaScript:**
```javascript
async function logout() {
  try {
    // If logout endpoint existed
    // await fetch('http://localhost:8000/herm-auth/api/v1/auth/logout', {
    //   method: 'POST',
    //   headers: {
    //     'Authorization': `Bearer ${sessionStorage.getItem('access_token')}`
    //   }
    // });

    // Clear all stored tokens
    sessionStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');

    // Clear application state
    clearUserData();

    // Redirect to login
    window.location.href = '/login';

  } catch (error) {
    console.error('Logout failed:', error);
    // Still clear local tokens even if server request fails
    sessionStorage.clear();
    window.location.href = '/login';
  }
}
```

**Python:**
```python
def logout():
    # Clear stored tokens
    access_token = None
    refresh_token = None

    # If logout endpoint existed:
    # requests.post(
    #     "http://localhost:8000/herm-auth/api/v1/auth/logout",
    #     headers={"Authorization": f"Bearer {access_token}"}
    # )

    print("Logged out successfully")
```

**Recommendation:** Implement server-side logout with token blacklisting using Redis for better security, especially in production environments handling sensitive data.

---

### 4. Making Authenticated Requests

**Objective:** Include authentication credentials in API requests to access protected endpoints.

#### Authorization Header Format

**Standard Bearer Token Authentication:**

```http
Authorization: Bearer <access_token>
```

**Components:**
- **Scheme:** `Bearer` (note the capital B)
- **Separator:** Single space
- **Token:** The access token JWT (do NOT use refresh token)

#### Step-by-Step Process

**Step 1: Extract Access Token from Storage**

```javascript
const accessToken = sessionStorage.getItem('access_token');
```

**Step 2: Add Authorization Header to Request**

```javascript
const response = await fetch('http://localhost:8000/herm-auth/api/v1/auth/me', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
  },
});
```

**Step 3: Server Validates Token**

*Implementation: `app/api/dependencies.py:11-28` and `app/services/user_service.py:89-118`*

1. **Extract Token** (`app/api/dependencies.py:12-16`):
   - FastAPI's `HTTPBearer` extracts token from Authorization header
   - Validates format is `Bearer <token>`

2. **Decode Token** (`app/core/security.py:67-75`):
   - Verify JWT signature using secret key
   - Decode payload
   - Return `None` if invalid or expired

3. **Validate Payload** (`app/services/user_service.py:92-103`):
   - Check payload is not `None`
   - Extract user ID from `sub` claim
   - Validate claim exists

4. **Fetch User** (`app/services/user_service.py:105-110`):
   - Query database for user by ID
   - Return 404 if user not found

5. **Check User Status** (`app/services/user_service.py:112-116`):
   - Verify `user.is_active == True`
   - Return 403 if inactive

6. **Return User Object**:
   - User object available as dependency in endpoint
   - Endpoint returns requested data

**Step 4: Handle Response**

```javascript
if (response.ok) {
  const data = await response.json();
  console.log('User data:', data);
} else if (response.status === 401) {
  // Token expired or invalid - redirect to login
  redirectToLogin();
} else if (response.status === 403) {
  // Account inactive
  alert('Your account has been deactivated');
}
```

#### Complete Examples

**JavaScript/Fetch:**

```javascript
async function getCurrentUser() {
  const accessToken = sessionStorage.getItem('access_token');

  if (!accessToken) {
    throw new Error('No access token found');
  }

  try {
    const response = await fetch('http://localhost:8000/herm-auth/api/v1/auth/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Unauthorized - please log in again');
      }
      const error = await response.json();
      throw new Error(error.detail);
    }

    return await response.json();
  } catch (error) {
    console.error('Failed to get user:', error);
    throw error;
  }
}

// Usage
getCurrentUser()
  .then(user => console.log('Current user:', user))
  .catch(error => console.error('Error:', error));
```

**Python/Requests:**

```python
import requests

def get_current_user(access_token: str) -> dict:
    """Get current user information using access token."""
    url = "http://localhost:8000/herm-auth/api/v1/auth/me"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 401:
        raise Exception("Unauthorized - please log in again")

    response.raise_for_status()
    return response.json()

# Usage
try:
    user_data = get_current_user(access_token)
    print(f"Current user: {user_data['email']}")
except Exception as e:
    print(f"Error: {e}")
```

**cURL:**

```bash
# Get current user
curl -X GET "http://localhost:8000/herm-auth/api/v1/auth/me" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Example with stored token variable
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
curl -X GET "http://localhost:8000/herm-auth/api/v1/auth/me" \
  -H "Authorization: Bearer ${TOKEN}"
```

#### Generic API Request Helper

**Reusable Authenticated Request Function:**

```javascript
async function authenticatedRequest(url, options = {}) {
  const accessToken = sessionStorage.getItem('access_token');

  if (!accessToken) {
    throw new Error('No access token - please log in');
  }

  // Merge authorization header with provided options
  const config = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
      ...(options.headers || {}),
    },
  };

  const response = await fetch(url, config);

  // Handle common error cases
  if (response.status === 401) {
    // Token expired - clear and redirect to login
    sessionStorage.removeItem('access_token');
    window.location.href = '/login';
    throw new Error('Session expired');
  }

  if (response.status === 403) {
    throw new Error('Access forbidden');
  }

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Request failed');
  }

  return response.json();
}

// Usage examples
await authenticatedRequest('http://localhost:8000/herm-auth/api/v1/auth/me');

await authenticatedRequest('http://localhost:8000/herm-auth/api/v1/some-endpoint', {
  method: 'POST',
  body: JSON.stringify({ data: 'value' }),
});
```

#### Common Mistakes to Avoid

❌ **Using refresh token instead of access token:**
```javascript
// WRONG
headers: {
  'Authorization': `Bearer ${refresh_token}` // Don't use refresh token!
}
```

✅ **Always use access token:**
```javascript
// CORRECT
headers: {
  'Authorization': `Bearer ${access_token}`
}
```

❌ **Missing Bearer prefix:**
```javascript
// WRONG
headers: {
  'Authorization': access_token
}
```

✅ **Include Bearer scheme:**
```javascript
// CORRECT
headers: {
  'Authorization': `Bearer ${access_token}`
}
```

❌ **Incorrect capitalization:**
```javascript
// WRONG
headers: {
  'Authorization': `bearer ${access_token}` // lowercase 'b'
}
```

✅ **Capital B in Bearer:**
```javascript
// CORRECT
headers: {
  'Authorization': `Bearer ${access_token}`
}
```

---

## Token Management Details

### Token Types Issued

The service issues **two distinct token types** upon successful authentication:

| Token Type | Purpose | Default Lifespan | Claims Included | Current Status |
|------------|---------|------------------|-----------------|----------------|
| **Access Token** | API authentication | 30 minutes | `sub`, `email`, `exp`, `type` | ✅ Fully functional |
| **Refresh Token** | Token renewal | 7 days | `sub`, `exp`, `type` | ⚠️ Issued but not usable |

### Token Format & Structure

Both tokens follow the **JWT (JSON Web Token)** standard with three parts:

```
header.payload.signature
```

#### Header Structure

**Both token types use the same header:**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Fields:**
- `alg`: Algorithm used for signing (HMAC SHA-256)
- `typ`: Token type (always JWT)

#### Access Token Payload

**Implementation:** `app/core/security.py:38-53`

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "exp": 1700308200,
  "type": "access"
}
```

**Claims Explained:**

| Claim | Name | Type | Description | Example |
|-------|------|------|-------------|---------|
| `sub` | Subject | UUID string | User's unique identifier | `"550e8400-e29b-41d4-a716-446655440000"` |
| `email` | Email | string | User's email address | `"user@example.com"` |
| `exp` | Expiration | Unix timestamp | Token expiration time | `1700308200` |
| `type` | Token Type | string | Identifies token purpose | `"access"` |

**Generation Logic:**
```python
# From app/core/security.py:38-53
expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
to_encode = {
    "sub": str(user_id),
    "email": email,
    "exp": expire,
    "type": "access"
}
encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
```

#### Refresh Token Payload

**Implementation:** `app/core/security.py:56-64`

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1700913000,
  "type": "refresh"
}
```

**Claims Explained:**

| Claim | Name | Type | Description |
|-------|------|------|-------------|
| `sub` | Subject | UUID string | User's unique identifier |
| `exp` | Expiration | Unix timestamp | Token expiration time |
| `type` | Token Type | string | Identifies token purpose (`"refresh"`) |

**Key Difference:** Refresh tokens **do not include** the `email` claim for security reasons (minimal information in long-lived tokens).

#### Signature

The signature is created by:

1. Taking the encoded header and payload
2. Signing with HMAC-SHA256 using the `SECRET_KEY`
3. Base64url encoding the result

**Verification:** `app/core/security.py:67-75`

```python
# Decode and verify signature
payload = jwt.decode(
    token,
    settings.SECRET_KEY,
    algorithms=[settings.ALGORITHM]
)
```

### Token Decoding Example

**JavaScript (Client-Side):**

```javascript
function decodeToken(token) {
  // Split token into parts
  const [header, payload, signature] = token.split('.');

  // Decode payload (base64url)
  const decodedPayload = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));

  return {
    userId: decodedPayload.sub,
    email: decodedPayload.email,
    expiresAt: new Date(decodedPayload.exp * 1000),
    tokenType: decodedPayload.type,
  };
}

// Usage
const accessToken = sessionStorage.getItem('access_token');
const decoded = decodeToken(accessToken);
console.log('Token expires at:', decoded.expiresAt);
```

**Python (Server-Side):**

A utility script is provided: `decode_token.py:1-40`

```python
# Usage example
from jose import jwt
from app.core.config import settings

def decode_token(token: str):
    """Decode and verify JWT token."""
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    return payload

# Decode token
token_data = decode_token(access_token)
print(f"User ID: {token_data['sub']}")
print(f"Email: {token_data['email']}")
print(f"Expires: {token_data['exp']}")
```

### Storage Recommendations

**Security Considerations:**

| Storage Method | Security | XSS Protection | CSRF Protection | Recommended For |
|----------------|----------|----------------|-----------------|-----------------|
| **Memory** | ⭐⭐⭐⭐⭐ | ✅ Yes | ✅ Yes | Single-page apps |
| **sessionStorage** | ⭐⭐⭐⭐ | ❌ No | ✅ Yes | Access tokens only |
| **localStorage** | ⭐⭐⭐ | ❌ No | ✅ Yes | Not recommended for sensitive data |
| **httpOnly Cookie** | ⭐⭐⭐⭐⭐ | ✅ Yes | ⚠️ Needs CSRF protection | Production environments |

#### Recommended Storage Strategy

**For Web Applications:**

```javascript
// Option 1: In-Memory Storage (Most Secure)
class TokenManager {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
  }

  setTokens(access, refresh) {
    this.accessToken = access;
    this.refreshToken = refresh;
  }

  getAccessToken() {
    return this.accessToken;
  }

  clear() {
    this.accessToken = null;
    this.refreshToken = null;
  }
}

const tokenManager = new TokenManager();

// After login
tokenManager.setTokens(accessToken, refreshToken);

// Making requests
fetch(url, {
  headers: {
    'Authorization': `Bearer ${tokenManager.getAccessToken()}`
  }
});
```

**For Production Web Apps (Hybrid Approach):**

```javascript
// Store access token in sessionStorage (survives page refresh)
// Store refresh token in httpOnly cookie (set by server)

// After login
sessionStorage.setItem('access_token', access_token);
// Refresh token stored in httpOnly cookie by server

// Making requests
const accessToken = sessionStorage.getItem('access_token');
fetch(url, {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  },
  credentials: 'include' // Send cookies
});
```

**For Mobile/Desktop Applications:**

Use secure platform-specific storage:
- **iOS:** Keychain
- **Android:** Keystore
- **Desktop (Electron):** safeStorage API

### Token Lifespan

**Default Configuration:** `app/core/config.py:23-24`

| Token Type | Configuration Variable | Default Value | Configurable Via |
|------------|----------------------|---------------|------------------|
| Access Token | `ACCESS_TOKEN_EXPIRE_MINUTES` | 30 minutes | Environment variable |
| Refresh Token | `REFRESH_TOKEN_EXPIRE_DAYS` | 7 days | Environment variable |

**Environment Variables:**

```bash
# .env file
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

**Customization Example:**

```bash
# Shorter access token (more secure, requires frequent refresh)
ACCESS_TOKEN_EXPIRE_MINUTES=15

# Longer refresh token (better UX, less secure)
REFRESH_TOKEN_EXPIRE_DAYS=30
```

**Security Trade-offs:**

| Lifespan | Security | User Experience |
|----------|----------|-----------------|
| **Short access tokens** (5-15 min) | ⭐⭐⭐⭐⭐ High | ⭐⭐ Fair (frequent refresh needed) |
| **Medium access tokens** (30-60 min) | ⭐⭐⭐⭐ Good | ⭐⭐⭐⭐ Good (default recommendation) |
| **Long access tokens** (>2 hours) | ⭐⭐ Low | ⭐⭐⭐⭐⭐ Excellent |
| **Short refresh tokens** (1-3 days) | ⭐⭐⭐⭐ Good | ⭐⭐⭐ Fair |
| **Long refresh tokens** (30+ days) | ⭐⭐ Low | ⭐⭐⭐⭐⭐ Excellent |

**Production Recommendations:**
- **Financial/Healthcare apps:** 15 min access, 1 day refresh
- **Standard business apps:** 30 min access, 7 day refresh (default)
- **Low-risk apps:** 1 hour access, 30 day refresh

### Expiration Handling

#### Detecting Token Expiration

**Method 1: Decode and Check (Client-Side)**

```javascript
function isTokenExpired(token) {
  if (!token) return true;

  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const currentTime = Math.floor(Date.now() / 1000);
    return payload.exp < currentTime;
  } catch (error) {
    return true; // Invalid token
  }
}

// Usage
const accessToken = sessionStorage.getItem('access_token');
if (isTokenExpired(accessToken)) {
  // Token expired - refresh or redirect to login
  redirectToLogin();
}
```

**Method 2: Proactive Refresh (Before Expiration)**

```javascript
function shouldRefreshToken(token, bufferMinutes = 5) {
  if (!token) return true;

  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const expirationTime = payload.exp * 1000; // Convert to ms
    const bufferTime = bufferMinutes * 60 * 1000;
    const currentTime = Date.now();

    // Refresh if within buffer window
    return currentTime > (expirationTime - bufferTime);
  } catch (error) {
    return true;
  }
}

// Check before important operations
if (shouldRefreshToken(accessToken)) {
  await refreshAccessToken(); // When implemented
}
```

**Method 3: Server Response (Reactive)**

```javascript
async function makeRequest(url, options) {
  const response = await fetch(url, options);

  if (response.status === 401) {
    const error = await response.json();
    if (error.detail === "Could not validate credentials") {
      // Token expired or invalid
      handleExpiredToken();
    }
  }

  return response;
}

function handleExpiredToken() {
  // Clear expired token
  sessionStorage.removeItem('access_token');

  // Attempt refresh (when implemented) or redirect to login
  window.location.href = '/login?reason=session_expired';
}
```

#### Expiration Error Responses

**When access token is expired or invalid:**

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "detail": "Could not validate credentials"
}
```

**Implementation:** `app/services/user_service.py:92-96`

**Causes:**
- Token signature verification failed
- Token has passed `exp` timestamp
- Token is malformed
- Secret key mismatch

#### Recommended Expiration Strategy

**Complete Token Lifecycle Management:**

```javascript
class AuthManager {
  constructor() {
    this.accessToken = null;
    this.tokenExpiresAt = null;
    this.refreshTimer = null;
  }

  setAccessToken(token) {
    this.accessToken = token;

    // Decode to get expiration
    const payload = JSON.parse(atob(token.split('.')[1]));
    this.tokenExpiresAt = new Date(payload.exp * 1000);

    // Schedule proactive refresh (5 minutes before expiration)
    this.scheduleRefresh();
  }

  scheduleRefresh() {
    // Clear existing timer
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    // Calculate time until refresh needed (5 min buffer)
    const bufferMs = 5 * 60 * 1000;
    const timeUntilRefresh = this.tokenExpiresAt.getTime() - Date.now() - bufferMs;

    if (timeUntilRefresh > 0) {
      this.refreshTimer = setTimeout(() => {
        this.refreshAccessToken();
      }, timeUntilRefresh);
    }
  }

  async refreshAccessToken() {
    // When refresh endpoint is implemented:
    // const newToken = await fetch('/auth/refresh', { ... });
    // this.setAccessToken(newToken.access_token);

    // Current workaround: redirect to login
    console.warn('Token expiring soon, refresh not implemented');
    window.location.href = '/login?reason=token_expiring';
  }

  getAccessToken() {
    // Check if token is expired
    if (!this.accessToken || Date.now() > this.tokenExpiresAt.getTime()) {
      throw new Error('Access token expired');
    }
    return this.accessToken;
  }

  clear() {
    this.accessToken = null;
    this.tokenExpiresAt = null;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
  }
}
```

### Authorization Header Format

**Standard Format:**

```http
Authorization: Bearer <access_token>
```

**Complete Specification:**

| Component | Value | Required | Case-Sensitive |
|-----------|-------|----------|----------------|
| Header Name | `Authorization` | Yes | No |
| Authentication Scheme | `Bearer` | Yes | First letter capitalized |
| Separator | Single space | Yes | Exactly one space |
| Token | JWT access token | Yes | Yes |

**Examples:**

✅ **Correct:**
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJleHAiOjE3MDAzMDgyMDAsInR5cGUiOiJhY2Nlc3MifQ.signature
```

❌ **Incorrect:**
```http
Authorization: eyJhbGc...          # Missing "Bearer"
Authorization: bearer eyJhbGc...  # Lowercase "bearer"
Authorization:Bearer eyJhbGc...   # Missing space
Authorization: Token eyJhbGc...   # Wrong scheme
Authorization: Bearer <refresh_token>  # Wrong token type
```

**Implementation Reference:**

- **FastAPI HTTPBearer:** `app/api/dependencies.py:8`
- **Token Extraction:** `app/api/dependencies.py:12-16`

```python
from fastapi.security import HTTPBearer

security = HTTPBearer()

# Automatically extracts and validates Bearer token format
credentials = Depends(security)
token = credentials.credentials
```

---

## Error Handling

### Authentication Error Codes

Comprehensive list of all authentication-related errors:

| Status Code | Error Message | Cause | Resolution |
|-------------|---------------|-------|------------|
| 400 | `Email already registered` | Email exists during signup | Use different email or login |
| 401 | `Incorrect email or password` | Invalid credentials during login | Check credentials |
| 401 | `Could not validate credentials` | Invalid/expired token | Refresh token or re-login |
| 401 | `Not authenticated` | Missing Authorization header | Include Bearer token |
| 403 | `User account is inactive` | Account deactivated | Contact support |
| 404 | `User not found` | User deleted after token issued | Re-login |
| 422 | Validation errors | Invalid request format | Fix request data |
| 500 | `Internal server error` | Unexpected server error | Retry or contact support |

### Error Response Formats

#### Standard Error Response

**Schema:** `app/schemas/user.py:70-72`

```json
{
  "detail": "Error message"
}
```

**Fields:**
- `detail` (string): Human-readable error description

#### Validation Error Response (422)

**Pydantic Validation Errors:**

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
- `type` (string): Error type identifier
- `loc` (array): Error location path
- `msg` (string): Human-readable error message
- `input` (any): The invalid input value
- `ctx` (object): Additional context (e.g., validation constraints)

**Common Validation Error Types:**

| Error Type | Description | Example |
|------------|-------------|---------|
| `string_too_short` | String below minimum length | Password < 8 chars |
| `string_too_long` | String exceeds maximum length | Password > 100 chars |
| `value_error` | Invalid value format | Invalid email format |
| `missing` | Required field not provided | Missing password field |

### Detecting Authentication Failures

#### Client-Side Error Detection

**HTTP Status Code Checking:**

```javascript
async function handleAuthRequest(url, options) {
  try {
    const response = await fetch(url, options);

    // Success
    if (response.ok) {
      return await response.json();
    }

    // Parse error
    const error = await response.json();

    // Check status code
    switch (response.status) {
      case 400:
        throw new BadRequestError(error.detail);

      case 401:
        throw new UnauthorizedError(error.detail);

      case 403:
        throw new ForbiddenError(error.detail);

      case 404:
        throw new NotFoundError(error.detail);

      case 422:
        throw new ValidationError(error.detail);

      case 500:
        throw new ServerError(error.detail);

      default:
        throw new Error(`Unexpected error: ${response.status}`);
    }
  } catch (error) {
    // Network error or parsing error
    if (error.name === 'TypeError') {
      throw new NetworkError('Network request failed');
    }
    throw error;
  }
}

// Custom error classes
class BadRequestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BadRequestError';
    this.status = 400;
  }
}

class UnauthorizedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UnauthorizedError';
    this.status = 401;
  }
}

class ForbiddenError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ForbiddenError';
    this.status = 403;
  }
}

// Usage
try {
  const data = await handleAuthRequest(url, options);
  console.log('Success:', data);
} catch (error) {
  if (error instanceof UnauthorizedError) {
    // Redirect to login
    redirectToLogin();
  } else if (error instanceof ValidationError) {
    // Show validation errors to user
    displayValidationErrors(error.message);
  } else {
    // Generic error handling
    console.error('Request failed:', error);
  }
}
```

### Token Expiration Detection

**Method 1: Decode Token Locally**

```javascript
function getTokenExpiration(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return {
      expiresAt: new Date(payload.exp * 1000),
      isExpired: Date.now() > payload.exp * 1000,
      expiresInSeconds: payload.exp - Math.floor(Date.now() / 1000),
    };
  } catch (error) {
    return {
      expiresAt: null,
      isExpired: true,
      expiresInSeconds: 0,
    };
  }
}

// Usage
const tokenInfo = getTokenExpiration(accessToken);
console.log('Token expires at:', tokenInfo.expiresAt);
console.log('Is expired:', tokenInfo.isExpired);
console.log('Expires in:', tokenInfo.expiresInSeconds, 'seconds');
```

**Method 2: Server Response Analysis**

```javascript
function isTokenExpirationError(response, errorData) {
  return (
    response.status === 401 &&
    errorData.detail === "Could not validate credentials"
  );
}

// Usage
const response = await fetch(url, options);
if (!response.ok) {
  const error = await response.json();
  if (isTokenExpirationError(response, error)) {
    console.log('Token expired or invalid');
    // Trigger refresh or re-login
  }
}
```

### Validation Error Handling

**Parsing and Displaying Validation Errors:**

```javascript
function parseValidationErrors(errorDetail) {
  // errorDetail is an array of validation error objects
  return errorDetail.map(error => ({
    field: error.loc[error.loc.length - 1], // Last item in location path
    message: error.msg,
    type: error.type,
    value: error.input,
  }));
}

// Usage
try {
  const response = await fetch(url, options);
  if (response.status === 422) {
    const errorData = await response.json();
    const errors = parseValidationErrors(errorData.detail);

    errors.forEach(error => {
      console.log(`${error.field}: ${error.message}`);
      // Display error next to form field
      displayFieldError(error.field, error.message);
    });
  }
} catch (error) {
  console.error('Request failed:', error);
}
```

**Example Output:**

```javascript
// Input: Validation error response
{
  "detail": [
    {
      "type": "string_too_short",
      "loc": ["body", "password"],
      "msg": "String should have at least 8 characters",
      "input": "short"
    },
    {
      "type": "value_error",
      "loc": ["body", "email"],
      "msg": "value is not a valid email address",
      "input": "invalid-email"
    }
  ]
}

// Output: Parsed errors
[
  {
    field: "password",
    message: "String should have at least 8 characters",
    type: "string_too_short",
    value: "short"
  },
  {
    field: "email",
    message: "value is not a valid email address",
    type: "value_error",
    value: "invalid-email"
  }
]
```

### Complete Error Handling Example

**Comprehensive Request Handler:**

```javascript
class APIClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const accessToken = sessionStorage.getItem('access_token');

    // Add authorization header if token exists
    const config = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(accessToken && { 'Authorization': `Bearer ${accessToken}` }),
        ...(options.headers || {}),
      },
    };

    try {
      const response = await fetch(url, config);

      if (response.ok) {
        return await response.json();
      }

      // Parse error response
      const errorData = await response.json();

      // Handle specific status codes
      switch (response.status) {
        case 400:
          throw new Error(`Bad Request: ${errorData.detail}`);

        case 401:
          // Check if token expired
          if (errorData.detail === "Could not validate credentials") {
            console.warn('Token expired or invalid');
            sessionStorage.removeItem('access_token');
            window.location.href = '/login?reason=session_expired';
          }
          throw new Error(`Unauthorized: ${errorData.detail}`);

        case 403:
          if (errorData.detail === "User account is inactive") {
            console.error('Account deactivated');
            window.location.href = '/account-inactive';
          }
          throw new Error(`Forbidden: ${errorData.detail}`);

        case 404:
          throw new Error(`Not Found: ${errorData.detail}`);

        case 422:
          const validationErrors = this.parseValidationErrors(errorData.detail);
          throw new ValidationError('Validation failed', validationErrors);

        case 500:
          throw new Error('Internal server error. Please try again later.');

        default:
          throw new Error(`Request failed with status ${response.status}`);
      }
    } catch (error) {
      // Network error
      if (error.name === 'TypeError') {
        throw new Error('Network error. Please check your connection.');
      }
      // Re-throw other errors
      throw error;
    }
  }

  parseValidationErrors(errors) {
    return errors.map(error => ({
      field: error.loc[error.loc.length - 1],
      message: error.msg,
      type: error.type,
    }));
  }

  // Convenience methods
  async get(endpoint) {
    return this.request(endpoint, { method: 'GET' });
  }

  async post(endpoint, data) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }
}

class ValidationError extends Error {
  constructor(message, errors) {
    super(message);
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

// Usage
const api = new APIClient('http://localhost:8000/herm-auth/api/v1');

// Login
try {
  const tokens = await api.post('/auth/login', {
    email: 'user@example.com',
    password: 'password123',
  });
  sessionStorage.setItem('access_token', tokens.access_token);
} catch (error) {
  if (error instanceof ValidationError) {
    error.errors.forEach(err => {
      console.log(`${err.field}: ${err.message}`);
    });
  } else {
    console.error('Login failed:', error.message);
  }
}

// Get current user
try {
  const user = await api.get('/auth/me');
  console.log('Current user:', user);
} catch (error) {
  console.error('Failed to get user:', error.message);
}
```

---

## Best Practices

### Security Best Practices

1. **Never Expose Tokens**
   - Don't log tokens in console or error messages
   - Don't include tokens in URLs or query parameters
   - Don't send tokens over unencrypted connections (use HTTPS)

2. **Secure Token Storage**
   - Use httpOnly cookies for production web apps
   - Use in-memory storage for sensitive applications
   - Never store tokens in localStorage for high-security apps
   - Clear tokens on logout

3. **Token Validation**
   - Always validate token expiration on client side
   - Implement proactive token refresh (before expiration)
   - Handle 401 errors gracefully
   - Don't trust client-side validation alone

4. **HTTPS Only**
   - Always use HTTPS in production
   - Tokens transmitted over HTTP can be intercepted
   - Configure secure cookies (Secure flag)

5. **Environment-Specific Secrets**
   - Use strong SECRET_KEY (32+ random characters)
   - Never commit secrets to version control
   - Rotate secrets regularly
   - Use different secrets per environment

### Client Implementation Best Practices

1. **Token Lifecycle Management**
   ```javascript
   // Good: Check expiration before requests
   if (isTokenExpiringSoon(token)) {
     await refreshToken();
   }

   // Bad: Make request with expired token
   await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
   ```

2. **Error Handling**
   ```javascript
   // Good: Specific error handling
   if (response.status === 401) {
     if (error.detail === "Could not validate credentials") {
       await handleExpiredToken();
     }
   }

   // Bad: Generic error handling
   if (!response.ok) {
     alert('Error occurred');
   }
   ```

3. **Token Refresh Strategy**
   ```javascript
   // Good: Proactive refresh with buffer
   const BUFFER_MINUTES = 5;
   if (tokenExpiresIn < BUFFER_MINUTES * 60) {
     await refreshToken();
   }

   // Bad: Reactive refresh after 401
   if (response.status === 401) {
     await refreshToken(); // Already failed
   }
   ```

4. **State Management**
   ```javascript
   // Good: Centralized token management
   class AuthManager {
     setTokens(access, refresh) { ... }
     getAccessToken() { ... }
     clear() { ... }
   }

   // Bad: Scattered token access
   sessionStorage.getItem('access_token'); // Everywhere in code
   ```

### Server Integration Best Practices

1. **Implement Missing Endpoints**
   - Add token refresh endpoint (high priority)
   - Add logout endpoint with token blacklisting
   - Add password reset flow
   - Add email verification

2. **Security Enhancements**
   - Implement rate limiting on auth endpoints
   - Add account lockout after failed attempts
   - Log authentication events
   - Monitor for suspicious activity

3. **Token Management**
   - Consider shorter access token lifespans
   - Implement token rotation on refresh
   - Use Redis for token blacklist
   - Add JTI (JWT ID) claim for tracking

4. **Production Configuration**
   - Set strong SECRET_KEY
   - Restrict CORS to specific origins
   - Enable HTTPS only
   - Configure proper logging

---

## Summary

This document covered the authentication flows and token management for the Herm Authentication Service:

- **Authentication System**: JWT-based with Bearer tokens
- **Login Flow**: Credentials → Validation → Token Generation → Response
- **Token Refresh**: ⚠️ Currently not implemented (requires development)
- **Logout**: ⚠️ Client-side only (no server-side revocation)
- **Authenticated Requests**: Bearer token in Authorization header
- **Token Types**: Access (30 min) and Refresh (7 days)
- **Error Handling**: Comprehensive error codes and formats
- **Best Practices**: Security, storage, and implementation guidelines

### Known Limitations

1. ⚠️ **No token refresh endpoint** - Refresh tokens cannot be used
2. ⚠️ **No logout endpoint** - Tokens cannot be revoked server-side
3. ⚠️ **No rate limiting** - Authentication endpoints unprotected
4. ⚠️ **No token rotation** - Refresh tokens don't rotate on use

### Next Steps

For complete integration, see:

- **Part 1:** Core API Documentation
- **Part 3:** OAuth Integration Guide (Coming Soon)
- **Part 4:** Connected Apps Management (Coming Soon)
- **Part 5:** Security Best Practices (Coming Soon)

---

**Document Version:** 1.0
**Last Updated:** 2025-11-18
**Service Version:** 1.0.0
