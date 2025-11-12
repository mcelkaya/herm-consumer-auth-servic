# API Documentation

## Base URL
```
http://localhost:8000/api/v1
```

## Authentication

All authenticated endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <access_token>
```

---

## Endpoints

### 1. User Signup

**POST** `/auth/signup`

Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (201):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Error Response (400):**
```json
{
  "detail": "Email already registered"
}
```

---

### 2. User Login

**POST** `/auth/login`

Authenticate and get access tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Error Response (401):**
```json
{
  "detail": "Incorrect email or password"
}
```

---

### 3. Get Current User

**GET** `/auth/me`

Get authenticated user information.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "is_active": true,
  "is_verified": false,
  "created_at": "2025-11-11T10:00:00Z"
}
```

---

### 4. Connect Email Provider

**POST** `/connected-apps`

Connect an email provider account.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "provider": "gmail",
  "provider_email": "myemail@gmail.com",
  "access_token": "ya29.a0AfH6SMBx...",
  "refresh_token": "1//0gKpX5...",
  "token_expires_at": "2025-11-11T12:00:00Z"
}
```

**Response (201):**
```json
{
  "id": "987e6543-e21b-12d3-a456-426614174111",
  "provider": "gmail",
  "provider_email": "myemail@gmail.com",
  "created_at": "2025-11-11T10:30:00Z",
  "updated_at": null
}
```

**Validation:**
- `provider` must be one of: `gmail`, `outlook`, `yahoo`
- `provider_email` must be a valid email
- `access_token` is required

---

### 5. List Connected Apps

**GET** `/connected-apps`

Get all connected email provider accounts.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "apps": [
    {
      "id": "987e6543-e21b-12d3-a456-426614174111",
      "provider": "gmail",
      "provider_email": "myemail@gmail.com",
      "created_at": "2025-11-11T10:30:00Z",
      "updated_at": null
    },
    {
      "id": "123e4567-e89b-12d3-a456-426614174222",
      "provider": "outlook",
      "provider_email": "myemail@outlook.com",
      "created_at": "2025-11-11T11:00:00Z",
      "updated_at": null
    }
  ],
  "total": 2
}
```

---

### 6. Delete Connected App

**DELETE** `/connected-apps/{app_id}`

Remove a connected email provider account.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Path Parameters:**
- `app_id` (UUID): ID of the connected app

**Response (200):**
```json
{
  "message": "Connected app deleted successfully"
}
```

**Error Response (404):**
```json
{
  "detail": "Connected app not found"
}
```

**Error Response (403):**
```json
{
  "detail": "Not authorized to delete this app"
}
```

---

### 7. Google OAuth Authorization

**GET** `/oauth/google/authorize`

Get Google OAuth authorization URL.

**Response (200):**
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=..."
}
```

**Usage:**
1. Redirect user to the `authorization_url`
2. User authorizes the application
3. Google redirects to callback URL with authorization code

---

### 8. Google OAuth Callback

**GET** `/oauth/google/callback?code=<authorization_code>`

Handle Google OAuth callback and connect the account.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `code` (string): Authorization code from Google

**Response (200):**
```json
{
  "id": "987e6543-e21b-12d3-a456-426614174111",
  "provider": "gmail",
  "provider_email": "user@gmail.com",
  "created_at": "2025-11-11T10:30:00Z",
  "updated_at": null
}
```

---

### 9. Microsoft OAuth Authorization

**GET** `/oauth/microsoft/authorize`

Get Microsoft OAuth authorization URL.

**Response (200):**
```json
{
  "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=..."
}
```

---

### 10. Microsoft OAuth Callback

**GET** `/oauth/microsoft/callback?code=<authorization_code>`

Handle Microsoft OAuth callback and connect the account.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `code` (string): Authorization code from Microsoft

**Response (200):**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174222",
  "provider": "outlook",
  "provider_email": "user@outlook.com",
  "created_at": "2025-11-11T11:00:00Z",
  "updated_at": null
}
```

---

### 11. Yahoo OAuth Authorization

**GET** `/oauth/yahoo/authorize`

Get Yahoo OAuth authorization URL.

**Response (200):**
```json
{
  "authorization_url": "https://api.login.yahoo.com/oauth2/request_auth?client_id=..."
}
```

---

### 12. Yahoo OAuth Callback

**GET** `/oauth/yahoo/callback?code=<authorization_code>`

Handle Yahoo OAuth callback and connect the account.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `code` (string): Authorization code from Yahoo

**Response (200):**
```json
{
  "id": "456e7890-e12b-34d5-a678-901234567333",
  "provider": "yahoo",
  "provider_email": "user@yahoo.com",
  "created_at": "2025-11-11T11:30:00Z",
  "updated_at": null
}
```

---

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Validation error message"
}
```

### 401 Unauthorized
```json
{
  "detail": "Could not validate credentials"
}
```

### 403 Forbidden
```json
{
  "detail": "Not authorized to perform this action"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 422 Unprocessable Entity
```json
{
  "detail": [
    {
      "loc": ["body", "email"],
      "msg": "value is not a valid email address",
      "type": "value_error.email"
    }
  ]
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error"
}
```

---

## OAuth Flow Example

### Gmail Integration Flow

1. **Get Authorization URL**
   ```bash
   curl -X GET http://localhost:8000/api/v1/oauth/google/authorize
   ```

2. **Redirect user to the authorization URL**
   User authorizes the application on Google's consent screen

3. **Handle callback**
   ```bash
   curl -X GET \
     'http://localhost:8000/api/v1/oauth/google/callback?code=4/0AY0e-g7...' \
     -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
   ```

4. **Gmail account is now connected**
   Access token is stored securely in the database

---

## Rate Limiting

- **Authentication endpoints**: 5 requests per minute per IP
- **OAuth endpoints**: 10 requests per minute per user
- **Other endpoints**: 100 requests per minute per user

---

## Security Headers

All responses include:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## CORS

CORS is enabled for all origins in development.
In production, configure allowed origins in environment variables.

---

## Webhooks (Future Feature)

Planned support for webhooks to notify your application when:
- New emails are received
- Email read status changes
- OAuth tokens are refreshed
