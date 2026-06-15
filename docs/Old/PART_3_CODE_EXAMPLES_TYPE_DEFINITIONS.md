# Part 3: Code Examples & Type Definitions

**Herm Authentication Service - Integration Guide**

---

## Table of Contents

1. [TypeScript Type Definitions](#typescript-type-definitions)
2. [Code Examples](#code-examples)
3. [Complete Integration Examples](#complete-integration-examples)
4. [Security Checklist](#security-checklist)

---

## TypeScript Type Definitions

### Core Types

```typescript
/**
 * User object returned from the API
 */
export interface User {
  id: string; // UUID
  email: string;
  is_active: boolean;
  is_verified: boolean;
  created_at: string; // ISO 8601 datetime
}

/**
 * Login request payload
 */
export interface LoginRequest {
  email: string;
  password: string;
}

/**
 * Login response containing authentication tokens
 */
export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string; // Always "bearer"
}

/**
 * Signup/Registration request payload
 */
export interface SignupRequest {
  email: string;
  password: string; // Min 8, max 100 characters
}

/**
 * Signup response containing authentication tokens
 */
export interface SignupResponse {
  access_token: string;
  refresh_token: string;
  token_type: string; // Always "bearer"
}

/**
 * Token refresh request payload
 * Note: This endpoint is not yet implemented in the service
 */
export interface RefreshTokenRequest {
  refresh_token: string;
}

/**
 * Token refresh response
 * Note: This endpoint is not yet implemented in the service
 */
export interface RefreshTokenResponse {
  access_token: string;
  token_type: string;
}
```

### Error Types

```typescript
/**
 * Standard error response from the API
 */
export interface ErrorResponse {
  detail: string;
}

/**
 * Validation error detail
 */
export interface ValidationErrorDetail {
  type: string;
  loc: Array<string | number>;
  msg: string;
  input?: any;
  ctx?: Record<string, any>;
}

/**
 * Validation error response (422)
 */
export interface ValidationErrorResponse {
  detail: ValidationErrorDetail[];
}

/**
 * Parsed validation error for easier handling
 */
export interface ParsedValidationError {
  field: string;
  message: string;
  type: string;
  input?: any;
}
```

### JWT Token Types

```typescript
/**
 * Decoded JWT access token payload
 */
export interface AccessTokenPayload {
  sub: string; // User ID (UUID)
  email: string;
  exp: number; // Unix timestamp
  type: "access";
}

/**
 * Decoded JWT refresh token payload
 */
export interface RefreshTokenPayload {
  sub: string; // User ID (UUID)
  exp: number; // Unix timestamp
  type: "refresh";
}

/**
 * Token expiration information
 */
export interface TokenExpirationInfo {
  expiresAt: Date;
  isExpired: boolean;
  expiresInSeconds: number;
}
```

### Connected Apps Types

```typescript
/**
 * OAuth provider types
 */
export type OAuthProvider = "gmail" | "outlook" | "yahoo";

/**
 * Connected app/email account
 */
export interface ConnectedApp {
  id: string; // UUID
  provider: OAuthProvider;
  provider_email: string;
  created_at: string; // ISO 8601 datetime
  updated_at: string | null; // ISO 8601 datetime
}

/**
 * Create connected app request
 */
export interface ConnectedAppCreate {
  provider: OAuthProvider;
  provider_email: string;
  access_token: string;
  refresh_token?: string | null;
  token_expires_at?: string | null; // ISO 8601 datetime
}

/**
 * List of connected apps response
 */
export interface ConnectedAppsList {
  apps: ConnectedApp[];
  total: number;
}
```

### API Configuration

```typescript
/**
 * API client configuration
 */
export interface APIConfig {
  baseURL: string;
  timeout?: number;
  headers?: Record<string, string>;
}

/**
 * Authentication configuration
 */
export interface AuthConfig {
  accessTokenKey?: string; // Storage key for access token
  refreshTokenKey?: string; // Storage key for refresh token
  storageType?: "sessionStorage" | "localStorage" | "memory";
  onUnauthorized?: () => void;
  onForbidden?: () => void;
}
```

---

## Code Examples

### 1. Login Function

#### Using Fetch

```typescript
/**
 * Login user and obtain authentication tokens
 */
async function login(
  email: string,
  password: string
): Promise<LoginResponse> {
  const url = "http://localhost:8000/herm-auth/api/v1/auth/login";

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    });

    // Handle error responses
    if (!response.ok) {
      const error: ErrorResponse = await response.json();

      switch (response.status) {
        case 401:
          throw new Error(`Authentication failed: ${error.detail}`);
        case 403:
          throw new Error(`Account inactive: ${error.detail}`);
        case 422:
          throw new Error(`Validation error: ${error.detail}`);
        default:
          throw new Error(`Login failed: ${error.detail}`);
      }
    }

    // Parse success response
    const data: LoginResponse = await response.json();

    // Store tokens
    sessionStorage.setItem("access_token", data.access_token);
    sessionStorage.setItem("refresh_token", data.refresh_token);

    return data;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error("Network error. Please check your connection.");
    }
    throw error;
  }
}

// Usage
try {
  const tokens = await login("user@example.com", "SecurePassword123!");
  console.log("Login successful!");
} catch (error) {
  console.error("Login failed:", error.message);
}
```

#### Using Axios

```typescript
import axios, { AxiosError } from "axios";

/**
 * Login user and obtain authentication tokens (Axios version)
 */
async function loginWithAxios(
  email: string,
  password: string
): Promise<LoginResponse> {
  const url = "http://localhost:8000/herm-auth/api/v1/auth/login";

  try {
    const response = await axios.post<LoginResponse>(
      url,
      { email, password },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    // Store tokens
    sessionStorage.setItem("access_token", response.data.access_token);
    sessionStorage.setItem("refresh_token", response.data.refresh_token);

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<ErrorResponse>;

      if (axiosError.response) {
        const status = axiosError.response.status;
        const detail = axiosError.response.data.detail;

        switch (status) {
          case 401:
            throw new Error(`Authentication failed: ${detail}`);
          case 403:
            throw new Error(`Account inactive: ${detail}`);
          case 422:
            throw new Error(`Validation error: ${detail}`);
          default:
            throw new Error(`Login failed: ${detail}`);
        }
      } else if (axiosError.request) {
        throw new Error("Network error. Please check your connection.");
      }
    }
    throw error;
  }
}
```

### 2. Authenticated Request Function

#### Using Fetch

```typescript
/**
 * Make an authenticated API request with automatic token attachment
 */
async function authenticatedRequest<T>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  // Get access token
  const accessToken = sessionStorage.getItem("access_token");

  if (!accessToken) {
    throw new Error("No access token found. Please log in.");
  }

  // Merge headers with authorization
  const config: RequestInit = {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
      ...(options.headers || {}),
    },
  };

  try {
    const response = await fetch(url, config);

    // Handle authentication errors
    if (response.status === 401) {
      // Clear expired token
      sessionStorage.removeItem("access_token");
      window.location.href = "/login?reason=session_expired";
      throw new Error("Session expired. Please log in again.");
    }

    if (response.status === 403) {
      const error: ErrorResponse = await response.json();
      throw new Error(`Access forbidden: ${error.detail}`);
    }

    if (!response.ok) {
      const error: ErrorResponse = await response.json();
      throw new Error(error.detail || "Request failed");
    }

    return await response.json();
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error("Network error. Please check your connection.");
    }
    throw error;
  }
}

// Usage: Get current user
const user = await authenticatedRequest<User>(
  "http://localhost:8000/herm-auth/api/v1/auth/me"
);
console.log("Current user:", user.email);
```

#### Using Axios

```typescript
import axios, { AxiosRequestConfig } from "axios";

/**
 * Make an authenticated API request with automatic token attachment (Axios)
 */
async function authenticatedRequestAxios<T>(
  url: string,
  config: AxiosRequestConfig = {}
): Promise<T> {
  // Get access token
  const accessToken = sessionStorage.getItem("access_token");

  if (!accessToken) {
    throw new Error("No access token found. Please log in.");
  }

  try {
    const response = await axios<T>({
      url,
      ...config,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
        ...(config.headers || {}),
      },
    });

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<ErrorResponse>;

      if (axiosError.response?.status === 401) {
        sessionStorage.removeItem("access_token");
        window.location.href = "/login?reason=session_expired";
        throw new Error("Session expired. Please log in again.");
      }

      if (axiosError.response?.status === 403) {
        throw new Error(
          `Access forbidden: ${axiosError.response.data.detail}`
        );
      }

      if (axiosError.response) {
        throw new Error(axiosError.response.data.detail || "Request failed");
      }

      throw new Error("Network error. Please check your connection.");
    }
    throw error;
  }
}
```

### 3. Token Refresh Logic

**Note:** The refresh endpoint is not yet implemented on the server. This is the expected implementation for when it becomes available.

```typescript
/**
 * Refresh access token using refresh token
 * Note: This endpoint is NOT YET IMPLEMENTED on the server
 */
async function refreshAccessToken(): Promise<string> {
  const refreshToken = sessionStorage.getItem("refresh_token");

  if (!refreshToken) {
    throw new Error("No refresh token found. Please log in again.");
  }

  const url = "http://localhost:8000/herm-auth/api/v1/auth/refresh";

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) {
      // Refresh token expired or invalid
      sessionStorage.removeItem("access_token");
      sessionStorage.removeItem("refresh_token");
      window.location.href = "/login?reason=session_expired";
      throw new Error("Refresh token expired. Please log in again.");
    }

    const data: RefreshTokenResponse = await response.json();

    // Store new access token
    sessionStorage.setItem("access_token", data.access_token);

    return data.access_token;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error("Network error. Please check your connection.");
    }
    throw error;
  }
}

/**
 * Auto-refresh token when it expires soon
 */
async function autoRefreshToken(): Promise<void> {
  const accessToken = sessionStorage.getItem("access_token");

  if (!accessToken) {
    return;
  }

  const tokenInfo = getTokenExpiration(accessToken);

  // Refresh if token expires in less than 5 minutes
  const REFRESH_BUFFER_SECONDS = 5 * 60;

  if (
    !tokenInfo.isExpired &&
    tokenInfo.expiresInSeconds < REFRESH_BUFFER_SECONDS
  ) {
    try {
      await refreshAccessToken();
      console.log("Token refreshed successfully");
    } catch (error) {
      console.error("Token refresh failed:", error);
    }
  }
}

/**
 * Get token expiration information
 */
function getTokenExpiration(token: string): TokenExpirationInfo {
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    const expiresAt = new Date(payload.exp * 1000);
    const now = Date.now();

    return {
      expiresAt,
      isExpired: now > payload.exp * 1000,
      expiresInSeconds: Math.max(0, payload.exp - Math.floor(now / 1000)),
    };
  } catch (error) {
    return {
      expiresAt: new Date(0),
      isExpired: true,
      expiresInSeconds: 0,
    };
  }
}

// Set up automatic token refresh every minute
setInterval(autoRefreshToken, 60 * 1000);
```

### 4. API Client/Service Class

#### Fetch-based API Service

```typescript
/**
 * Complete authentication API client using Fetch
 */
class AuthAPIClient {
  private baseURL: string;
  private accessTokenKey: string;
  private refreshTokenKey: string;

  constructor(
    baseURL: string = "http://localhost:8000/herm-auth/api/v1",
    config: Partial<AuthConfig> = {}
  ) {
    this.baseURL = baseURL;
    this.accessTokenKey = config.accessTokenKey || "access_token";
    this.refreshTokenKey = config.refreshTokenKey || "refresh_token";
  }

  /**
   * Login user
   */
  async login(email: string, password: string): Promise<LoginResponse> {
    const response = await fetch(`${this.baseURL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error: ErrorResponse = await response.json();
      throw new Error(error.detail);
    }

    const data: LoginResponse = await response.json();

    // Store tokens
    sessionStorage.setItem(this.accessTokenKey, data.access_token);
    sessionStorage.setItem(this.refreshTokenKey, data.refresh_token);

    return data;
  }

  /**
   * Sign up new user
   */
  async signup(email: string, password: string): Promise<SignupResponse> {
    const response = await fetch(`${this.baseURL}/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error: ErrorResponse | ValidationErrorResponse =
        await response.json();

      if (response.status === 422) {
        // Handle validation errors
        const validationError = error as ValidationErrorResponse;
        const errors = this.parseValidationErrors(validationError.detail);
        throw new Error(
          errors.map((e) => `${e.field}: ${e.message}`).join(", ")
        );
      }

      throw new Error((error as ErrorResponse).detail);
    }

    const data: SignupResponse = await response.json();

    // Store tokens
    sessionStorage.setItem(this.accessTokenKey, data.access_token);
    sessionStorage.setItem(this.refreshTokenKey, data.refresh_token);

    return data;
  }

  /**
   * Get current authenticated user
   */
  async getCurrentUser(): Promise<User> {
    return this.authenticatedRequest<User>(`${this.baseURL}/auth/me`);
  }

  /**
   * Logout user (client-side only)
   */
  logout(): void {
    sessionStorage.removeItem(this.accessTokenKey);
    sessionStorage.removeItem(this.refreshTokenKey);
  }

  /**
   * Make authenticated request
   */
  private async authenticatedRequest<T>(
    url: string,
    options: RequestInit = {}
  ): Promise<T> {
    const accessToken = sessionStorage.getItem(this.accessTokenKey);

    if (!accessToken) {
      throw new Error("No access token found. Please log in.");
    }

    const config: RequestInit = {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
        ...(options.headers || {}),
      },
    };

    const response = await fetch(url, config);

    if (response.status === 401) {
      sessionStorage.removeItem(this.accessTokenKey);
      throw new Error("Session expired. Please log in again.");
    }

    if (!response.ok) {
      const error: ErrorResponse = await response.json();
      throw new Error(error.detail);
    }

    return await response.json();
  }

  /**
   * Parse validation errors
   */
  private parseValidationErrors(
    errors: ValidationErrorDetail[]
  ): ParsedValidationError[] {
    return errors.map((error) => ({
      field: String(error.loc[error.loc.length - 1]),
      message: error.msg,
      type: error.type,
      input: error.input,
    }));
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const accessToken = sessionStorage.getItem(this.accessTokenKey);

    if (!accessToken) {
      return false;
    }

    const tokenInfo = getTokenExpiration(accessToken);
    return !tokenInfo.isExpired;
  }
}

// Usage
const authClient = new AuthAPIClient();

// Login
await authClient.login("user@example.com", "SecurePassword123!");

// Get current user
const user = await authClient.getCurrentUser();
console.log("Logged in as:", user.email);

// Logout
authClient.logout();
```

#### Axios-based API Service

```typescript
import axios, { AxiosInstance, AxiosError } from "axios";

/**
 * Complete authentication API client using Axios
 */
class AuthAPIClientAxios {
  private client: AxiosInstance;
  private accessTokenKey: string;
  private refreshTokenKey: string;

  constructor(
    baseURL: string = "http://localhost:8000/herm-auth/api/v1",
    config: Partial<AuthConfig> = {}
  ) {
    this.accessTokenKey = config.accessTokenKey || "access_token";
    this.refreshTokenKey = config.refreshTokenKey || "refresh_token";

    this.client = axios.create({
      baseURL,
      timeout: config.timeout || 10000,
      headers: {
        "Content-Type": "application/json",
        ...config.headers,
      },
    });

    // Add request interceptor to attach token
    this.client.interceptors.request.use((config) => {
      const token = sessionStorage.getItem(this.accessTokenKey);
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError<ErrorResponse>) => {
        if (error.response?.status === 401) {
          sessionStorage.removeItem(this.accessTokenKey);
          sessionStorage.removeItem(this.refreshTokenKey);
          // Optionally redirect to login
          // window.location.href = '/login?reason=session_expired';
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * Login user
   */
  async login(email: string, password: string): Promise<LoginResponse> {
    try {
      const response = await this.client.post<LoginResponse>("/auth/login", {
        email,
        password,
      });

      // Store tokens
      sessionStorage.setItem(this.accessTokenKey, response.data.access_token);
      sessionStorage.setItem(
        this.refreshTokenKey,
        response.data.refresh_token
      );

      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Sign up new user
   */
  async signup(email: string, password: string): Promise<SignupResponse> {
    try {
      const response = await this.client.post<SignupResponse>("/auth/signup", {
        email,
        password,
      });

      // Store tokens
      sessionStorage.setItem(this.accessTokenKey, response.data.access_token);
      sessionStorage.setItem(
        this.refreshTokenKey,
        response.data.refresh_token
      );

      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get current authenticated user
   */
  async getCurrentUser(): Promise<User> {
    try {
      const response = await this.client.get<User>("/auth/me");
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Logout user (client-side only)
   */
  logout(): void {
    sessionStorage.removeItem(this.accessTokenKey);
    sessionStorage.removeItem(this.refreshTokenKey);
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const accessToken = sessionStorage.getItem(this.accessTokenKey);

    if (!accessToken) {
      return false;
    }

    const tokenInfo = getTokenExpiration(accessToken);
    return !tokenInfo.isExpired;
  }

  /**
   * Handle Axios errors
   */
  private handleError(error: unknown): Error {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<ErrorResponse>;

      if (axiosError.response) {
        return new Error(
          axiosError.response.data.detail || "Request failed"
        );
      }

      if (axiosError.request) {
        return new Error("Network error. Please check your connection.");
      }
    }

    return error instanceof Error ? error : new Error("Unknown error");
  }
}

// Usage
const authClient = new AuthAPIClientAxios();

// Login
await authClient.login("user@example.com", "SecurePassword123!");

// Get current user
const user = await authClient.getCurrentUser();
console.log("Logged in as:", user.email);

// Logout
authClient.logout();
```

### 5. Axios/Fetch Interceptor

#### Axios Interceptors (Advanced)

```typescript
import axios, { AxiosInstance, InternalAxiosRequestConfig } from "axios";

/**
 * Create Axios instance with automatic token attachment and refresh
 */
function createAuthenticatedAxiosClient(
  baseURL: string = "http://localhost:8000/herm-auth/api/v1"
): AxiosInstance {
  const client = axios.create({
    baseURL,
    timeout: 10000,
    headers: {
      "Content-Type": "application/json",
    },
  });

  // Request interceptor - attach access token
  client.interceptors.request.use(
    (config: InternalAxiosRequestConfig) => {
      const accessToken = sessionStorage.getItem("access_token");

      if (accessToken && config.headers) {
        config.headers.Authorization = `Bearer ${accessToken}`;
      }

      return config;
    },
    (error) => {
      return Promise.reject(error);
    }
  );

  // Response interceptor - handle errors and token refresh
  client.interceptors.response.use(
    (response) => {
      // Return successful responses as-is
      return response;
    },
    async (error) => {
      const originalRequest = error.config;

      // Handle 401 Unauthorized (token expired)
      if (error.response?.status === 401 && !originalRequest._retry) {
        originalRequest._retry = true;

        try {
          // Attempt to refresh token
          // Note: This endpoint is NOT YET IMPLEMENTED
          const refreshToken = sessionStorage.getItem("refresh_token");

          if (!refreshToken) {
            throw new Error("No refresh token available");
          }

          const response = await axios.post(
            `${baseURL}/auth/refresh`,
            { refresh_token: refreshToken }
          );

          const newAccessToken = response.data.access_token;

          // Store new access token
          sessionStorage.setItem("access_token", newAccessToken);

          // Update authorization header
          originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;

          // Retry original request
          return client(originalRequest);
        } catch (refreshError) {
          // Refresh failed - clear tokens and redirect to login
          sessionStorage.removeItem("access_token");
          sessionStorage.removeItem("refresh_token");
          window.location.href = "/login?reason=session_expired";

          return Promise.reject(refreshError);
        }
      }

      // Handle 403 Forbidden (account inactive)
      if (error.response?.status === 403) {
        console.error("Account inactive or forbidden");
        // Optionally redirect to account inactive page
      }

      return Promise.reject(error);
    }
  );

  return client;
}

// Usage
const apiClient = createAuthenticatedAxiosClient();

// All requests automatically include access token
const user = await apiClient.get<User>("/auth/me");
console.log("Current user:", user.data);

// If token expires during request, it will automatically:
// 1. Attempt to refresh the token (when endpoint is implemented)
// 2. Retry the original request with new token
// 3. Or redirect to login if refresh fails
```

#### Fetch Wrapper with Interceptor Pattern

```typescript
/**
 * Fetch wrapper with automatic token attachment and error handling
 */
class FetchClient {
  private baseURL: string;
  private beforeRequest?: (config: RequestInit) => RequestInit | Promise<RequestInit>;
  private afterResponse?: (response: Response) => Response | Promise<Response>;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
  }

  /**
   * Set request interceptor
   */
  setBeforeRequest(
    interceptor: (config: RequestInit) => RequestInit | Promise<RequestInit>
  ): void {
    this.beforeRequest = interceptor;
  }

  /**
   * Set response interceptor
   */
  setAfterResponse(
    interceptor: (response: Response) => Response | Promise<Response>
  ): void {
    this.afterResponse = interceptor;
  }

  /**
   * Make request with interceptors
   */
  async request<T>(endpoint: string, config: RequestInit = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;

    // Apply request interceptor
    let finalConfig = config;
    if (this.beforeRequest) {
      finalConfig = await this.beforeRequest(config);
    }

    let response = await fetch(url, finalConfig);

    // Apply response interceptor
    if (this.afterResponse) {
      response = await this.afterResponse(response);
    }

    if (!response.ok) {
      const error: ErrorResponse = await response.json();
      throw new Error(error.detail);
    }

    return await response.json();
  }

  async get<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: "GET" });
  }

  async post<T>(endpoint: string, data: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }
}

// Create client with interceptors
const fetchClient = new FetchClient("http://localhost:8000/herm-auth/api/v1");

// Request interceptor - attach token
fetchClient.setBeforeRequest((config) => {
  const accessToken = sessionStorage.getItem("access_token");

  return {
    ...config,
    headers: {
      "Content-Type": "application/json",
      ...(accessToken && { Authorization: `Bearer ${accessToken}` }),
      ...(config.headers || {}),
    },
  };
});

// Response interceptor - handle errors
fetchClient.setAfterResponse(async (response) => {
  if (response.status === 401) {
    sessionStorage.removeItem("access_token");
    window.location.href = "/login?reason=session_expired";
  }

  return response;
});

// Usage
const user = await fetchClient.get<User>("/auth/me");
console.log("Current user:", user);
```

---

## Complete Integration Examples

### React Integration

```typescript
import React, { createContext, useContext, useState, useEffect } from "react";

/**
 * Authentication context type
 */
interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
}

/**
 * Authentication context
 */
const AuthContext = createContext<AuthContextType | undefined>(undefined);

/**
 * Authentication provider component
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const authClient = new AuthAPIClient();

  // Check authentication on mount
  useEffect(() => {
    async function checkAuth() {
      try {
        if (authClient.isAuthenticated()) {
          const currentUser = await authClient.getCurrentUser();
          setUser(currentUser);
        }
      } catch (error) {
        console.error("Auth check failed:", error);
        authClient.logout();
      } finally {
        setIsLoading(false);
      }
    }

    checkAuth();
  }, []);

  const login = async (email: string, password: string) => {
    await authClient.login(email, password);
    const currentUser = await authClient.getCurrentUser();
    setUser(currentUser);
  };

  const signup = async (email: string, password: string) => {
    await authClient.signup(email, password);
    const currentUser = await authClient.getCurrentUser();
    setUser(currentUser);
  };

  const logout = () => {
    authClient.logout();
    setUser(null);
    window.location.href = "/login";
  };

  const value: AuthContextType = {
    user,
    login,
    signup,
    logout,
    isAuthenticated: !!user,
    isLoading,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * Custom hook to use authentication
 */
export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

// Usage in components
function LoginForm() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      await login(email, password);
      // Redirect handled by login function
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && <div className="error">{error}</div>}
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
        required
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
        required
      />
      <button type="submit">Login</button>
    </form>
  );
}

function UserProfile() {
  const { user, logout } = useAuth();

  if (!user) {
    return <div>Not logged in</div>;
  }

  return (
    <div>
      <h2>Profile</h2>
      <p>Email: {user.email}</p>
      <p>Account Status: {user.is_active ? "Active" : "Inactive"}</p>
      <p>Email Verified: {user.is_verified ? "Yes" : "No"}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

### Vue 3 Integration

```typescript
import { ref, computed, readonly } from "vue";

/**
 * Composable for authentication
 */
export function useAuthService() {
  const user = ref<User | null>(null);
  const isLoading = ref(false);

  const authClient = new AuthAPIClient();

  const isAuthenticated = computed(() => !!user.value);

  async function login(email: string, password: string): Promise<void> {
    isLoading.value = true;
    try {
      await authClient.login(email, password);
      user.value = await authClient.getCurrentUser();
    } finally {
      isLoading.value = false;
    }
  }

  async function signup(email: string, password: string): Promise<void> {
    isLoading.value = true;
    try {
      await authClient.signup(email, password);
      user.value = await authClient.getCurrentUser();
    } finally {
      isLoading.value = false;
    }
  }

  function logout(): void {
    authClient.logout();
    user.value = null;
  }

  async function checkAuth(): Promise<void> {
    isLoading.value = true;
    try {
      if (authClient.isAuthenticated()) {
        user.value = await authClient.getCurrentUser();
      }
    } catch (error) {
      console.error("Auth check failed:", error);
      logout();
    } finally {
      isLoading.value = false;
    }
  }

  return {
    user: readonly(user),
    isAuthenticated,
    isLoading: readonly(isLoading),
    login,
    signup,
    logout,
    checkAuth,
  };
}
```

### Angular Service

```typescript
import { Injectable } from "@angular/core";
import { BehaviorSubject, Observable } from "rxjs";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  private userSubject = new BehaviorSubject<User | null>(null);
  public user$: Observable<User | null> = this.userSubject.asObservable();

  private authClient = new AuthAPIClient();

  get isAuthenticated(): boolean {
    return this.authClient.isAuthenticated();
  }

  get currentUser(): User | null {
    return this.userSubject.value;
  }

  async login(email: string, password: string): Promise<void> {
    await this.authClient.login(email, password);
    const user = await this.authClient.getCurrentUser();
    this.userSubject.next(user);
  }

  async signup(email: string, password: string): Promise<void> {
    await this.authClient.signup(email, password);
    const user = await this.authClient.getCurrentUser();
    this.userSubject.next(user);
  }

  logout(): void {
    this.authClient.logout();
    this.userSubject.next(null);
  }

  async checkAuth(): Promise<void> {
    try {
      if (this.authClient.isAuthenticated()) {
        const user = await this.authClient.getCurrentUser();
        this.userSubject.next(user);
      }
    } catch (error) {
      console.error("Auth check failed:", error);
      this.logout();
    }
  }
}
```

---

## Security Checklist

### CSRF Protection

- ✅ **JWT tokens are immune to CSRF** by default when stored in `sessionStorage` or `localStorage`
- ⚠️ **If using cookies**, implement CSRF tokens:
  - Add `SameSite=Strict` or `SameSite=Lax` cookie attribute
  - Use CSRF token for state-changing operations
  - Verify `Origin` and `Referer` headers on server

**Implementation:**
```typescript
// If using cookies for tokens
document.cookie = `access_token=${token}; SameSite=Strict; Secure; HttpOnly`;
```

### XSS Prevention

- ✅ **Never use `localStorage` for sensitive data** - accessible to all JavaScript
- ✅ **Prefer `sessionStorage` or in-memory storage** for access tokens
- ✅ **Use `httpOnly` cookies** when possible (not accessible to JavaScript)
- ✅ **Sanitize user input** before displaying
- ✅ **Use Content Security Policy (CSP)** headers
- ⚠️ **Never store tokens in URL parameters**

**Best Practices:**
```typescript
// Good: In-memory storage
class TokenManager {
  private accessToken: string | null = null;

  setToken(token: string) {
    this.accessToken = token;
  }
}

// Acceptable: sessionStorage (clears on tab close)
sessionStorage.setItem("access_token", token);

// Bad: localStorage for sensitive apps
localStorage.setItem("access_token", token); // Vulnerable to XSS
```

### Secure Storage Recommendations

| Storage Method | Security Level | XSS Protection | Persistence | Use Case |
|----------------|---------------|----------------|-------------|----------|
| **In-Memory** | ⭐⭐⭐⭐⭐ Highest | ✅ Yes | ❌ Lost on refresh | SPAs, High security |
| **httpOnly Cookie** | ⭐⭐⭐⭐⭐ Highest | ✅ Yes | ✅ Yes | Production web apps |
| **sessionStorage** | ⭐⭐⭐⭐ Good | ❌ No | ⚠️ Tab only | Standard web apps |
| **localStorage** | ⭐⭐⭐ Fair | ❌ No | ✅ Yes | Low-risk applications |

**Recommended Implementation:**
```typescript
// Production-ready token storage strategy
class SecureTokenStorage {
  // Access token in sessionStorage (survives refresh)
  setAccessToken(token: string): void {
    sessionStorage.setItem("access_token", token);
  }

  getAccessToken(): string | null {
    return sessionStorage.getItem("access_token");
  }

  // Refresh token should be httpOnly cookie (set by server)
  // Or use secure platform storage for mobile apps

  clearTokens(): void {
    sessionStorage.removeItem("access_token");
    // Server should clear httpOnly cookie
  }
}
```

### Password Requirements

Based on the service implementation (`app/schemas/user.py:10`):

- ✅ **Minimum length**: 8 characters
- ✅ **Maximum length**: 100 characters
- ⚠️ **No complexity requirements** enforced (should add)

**Recommended Password Policy:**
```typescript
/**
 * Password validation with security requirements
 */
function validatePassword(password: string): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Length check
  if (password.length < 8) {
    errors.push("Password must be at least 8 characters");
  }

  if (password.length > 100) {
    errors.push("Password must not exceed 100 characters");
  }

  // Recommended: Add complexity requirements
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }

  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }

  if (!/[0-9]/.test(password)) {
    errors.push("Password must contain at least one number");
  }

  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push("Password must contain at least one special character");
  }

  // Check for common passwords (implement dictionary check)
  const commonPasswords = [
    "password",
    "123456",
    "12345678",
    "qwerty",
    "password123",
  ];
  if (commonPasswords.includes(password.toLowerCase())) {
    errors.push("Password is too common");
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
}

// Usage in signup form
const passwordCheck = validatePassword(password);
if (!passwordCheck.isValid) {
  console.error("Password validation failed:", passwordCheck.errors);
}
```

### Additional Security Best Practices

1. **Always Use HTTPS**
   ```typescript
   // Redirect HTTP to HTTPS
   if (window.location.protocol === "http:" && window.location.hostname !== "localhost") {
     window.location.href = window.location.href.replace("http:", "https:");
   }
   ```

2. **Implement Token Expiration Checking**
   ```typescript
   // Check token expiration before making requests
   function isTokenValid(token: string): boolean {
     try {
       const payload = JSON.parse(atob(token.split(".")[1]));
       return Date.now() < payload.exp * 1000;
     } catch {
       return false;
     }
   }
   ```

3. **Clear Tokens on Logout**
   ```typescript
   function secureLogout(): void {
     // Clear all storage
     sessionStorage.clear();
     localStorage.clear();

     // Redirect to login
     window.location.href = "/login";
   }
   ```

4. **Validate JWT Structure**
   ```typescript
   function isValidJWT(token: string): boolean {
     const parts = token.split(".");
     return parts.length === 3;
   }
   ```

5. **Monitor for Token Theft**
   ```typescript
   // Log authentication events
   function trackAuthEvent(event: string, metadata?: any): void {
     console.log(`[Auth] ${event}`, metadata);
     // Send to analytics/security monitoring
   }

   trackAuthEvent("login_success", { email: user.email });
   trackAuthEvent("token_refresh", { timestamp: new Date() });
   trackAuthEvent("suspicious_activity", { reason: "multiple_failed_logins" });
   ```

6. **Implement Rate Limiting (Client-Side)**
   ```typescript
   class RateLimiter {
     private attempts: number = 0;
     private resetTime: number = 0;

     canAttempt(): boolean {
       if (Date.now() > this.resetTime) {
         this.attempts = 0;
         this.resetTime = Date.now() + 60000; // 1 minute
       }

       return this.attempts < 5; // Max 5 attempts per minute
     }

     recordAttempt(): void {
       this.attempts++;
     }
   }

   const loginLimiter = new RateLimiter();

   async function login(email: string, password: string) {
     if (!loginLimiter.canAttempt()) {
       throw new Error("Too many login attempts. Please try again later.");
     }

     loginLimiter.recordAttempt();
     // ... proceed with login
   }
   ```

### Environment-Specific Configuration

```typescript
/**
 * Environment-based API configuration
 */
const API_CONFIG = {
  development: {
    baseURL: "http://localhost:8000/herm-auth/api/v1",
    timeout: 30000,
  },
  staging: {
    baseURL: "https://staging-api.yourdomain.com/herm-auth/api/v1",
    timeout: 10000,
  },
  production: {
    baseURL: "https://api.yourdomain.com/herm-auth/api/v1",
    timeout: 10000,
  },
};

const environment = process.env.NODE_ENV || "development";
const config = API_CONFIG[environment];

const authClient = new AuthAPIClient(config.baseURL);
```

---

## Summary

This document provides:

- ✅ **Complete TypeScript type definitions** for all API requests and responses
- ✅ **Production-ready code examples** using both Fetch and Axios
- ✅ **Reusable API client classes** with error handling
- ✅ **Interceptor patterns** for automatic token management
- ✅ **Framework integration examples** (React, Vue, Angular)
- ✅ **Comprehensive security checklist** with implementation examples

### Key Takeaways

1. **Store access tokens securely** - prefer `sessionStorage` or `httpOnly` cookies
2. **Implement token expiration checking** before making requests
3. **Handle 401 errors gracefully** - clear tokens and redirect to login
4. **Never expose tokens** in logs, URLs, or error messages
5. **Always use HTTPS** in production
6. **Validate passwords** with strong requirements
7. **Implement client-side rate limiting** for login attempts

### Next Steps

For complete integration documentation, see:

- **Part 1:** Core API Documentation - Endpoint reference and authentication basics
- **Part 2:** Authentication Flows & Token Management - Detailed flow explanations
- **Part 4:** OAuth Integration - Email provider integration (Coming Soon)
- **Part 5:** Deployment & Production Configuration (Coming Soon)

---

**Document Version:** 1.0
**Last Updated:** 2025-11-18
**Service Version:** 1.0.0
