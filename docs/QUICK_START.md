# Quick Start Guide

Get the Email Integration Service up and running in 5 minutes!

## Prerequisites

- Python 3.11+
- Docker Desktop
- Git

## Option 1: Docker Compose (Recommended)

### Step 1: Clone and Setup
```bash
git clone <repository-url>
cd email-integration-service
cp .env.example .env
```

### Step 2: Configure OAuth Credentials

Edit `.env` file and add your OAuth credentials:

```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/oauth/google/callback

# Microsoft OAuth
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_REDIRECT_URI=http://localhost:8000/api/v1/oauth/microsoft/callback

# Yahoo OAuth
YAHOO_CLIENT_ID=your-yahoo-client-id
YAHOO_CLIENT_SECRET=your-yahoo-client-secret
YAHOO_REDIRECT_URI=http://localhost:8000/api/v1/oauth/yahoo/callback
```

### Step 3: Start Services
```bash
docker-compose up -d
```

### Step 4: Run Migrations
```bash
docker-compose exec app alembic upgrade head
```

### Step 5: Test the API
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Email Integration Service",
  "version": "1.0.0"
}
```

### View API Documentation
Open your browser: http://localhost:8000/docs

---

## Option 2: Local Development

### Step 1: Setup Environment
```bash
git clone <repository-url>
cd email-integration-service

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Start PostgreSQL and Redis
```bash
# Using Docker
docker run -d --name postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=email_integration \
  -p 5432:5432 postgres:15-alpine

docker run -d --name redis \
  -p 6379:6379 redis:7-alpine
```

### Step 3: Configure Environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

### Step 4: Run Migrations
```bash
alembic upgrade head
```

### Step 5: Start Application
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Testing the API

### 1. Create a User Account
```bash
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpassword123"
  }'
```

### 2. Login
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpassword123"
  }'
```

Save the `access_token` from the response.

### 3. Get Current User
```bash
curl -X GET http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer <your-access-token>"
```

### 4. Connect Gmail Account

Get authorization URL:
```bash
curl -X GET http://localhost:8000/api/v1/oauth/google/authorize
```

Visit the URL in your browser, authorize, and you'll be redirected with a code.

Complete the connection:
```bash
curl -X GET "http://localhost:8000/api/v1/oauth/google/callback?code=<authorization-code>" \
  -H "Authorization: Bearer <your-access-token>"
```

### 5. List Connected Apps
```bash
curl -X GET http://localhost:8000/api/v1/connected-apps \
  -H "Authorization: Bearer <your-access-token>"
```

---

## Running Tests

### All Tests
```bash
# Using Docker
docker-compose exec app pytest

# Local
pytest
```

### With Coverage
```bash
# Using Docker
docker-compose exec app pytest --cov=app --cov-report=html

# Local
pytest --cov=app --cov-report=html
```

View coverage report: `open htmlcov/index.html`

### Specific Test Types
```bash
# Unit tests
pytest tests/unit -v

# Integration tests
pytest tests/integration -v
```

---

## Common Commands

### Using Makefile
```bash
make help          # Show all available commands
make install       # Install dependencies
make dev           # Run development server
make test          # Run tests
make test-cov      # Run tests with coverage
make docker-up     # Start Docker containers
make docker-down   # Stop Docker containers
make migrate-up    # Run database migrations
make lint          # Run linting
make format        # Format code
```

### Database Migrations
```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback last migration
alembic downgrade -1

# Show migration history
alembic history
```

### Docker Commands
```bash
# View logs
docker-compose logs -f app

# Access app container
docker-compose exec app bash

# Restart services
docker-compose restart

# Stop all services
docker-compose down

# Remove all containers and volumes
docker-compose down -v
```

---

## Obtaining OAuth Credentials

### Google (Gmail)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable Gmail API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `http://localhost:8000/api/v1/oauth/google/callback`
6. Copy Client ID and Client Secret

### Microsoft (Outlook)

1. Go to [Azure Portal](https://portal.azure.com/)
2. Register a new application
3. Add platform: Web
4. Add redirect URI: `http://localhost:8000/api/v1/oauth/microsoft/callback`
5. API Permissions: Add Mail.Read, User.Read
6. Create a client secret
7. Copy Application (client) ID and Client Secret

### Yahoo

1. Go to [Yahoo Developer Network](https://developer.yahoo.com/)
2. Create a new app
3. Select required APIs
4. Add redirect URI: `http://localhost:8000/api/v1/oauth/yahoo/callback`
5. Copy Client ID and Client Secret

---

## Troubleshooting

### Database Connection Error
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check connection
psql -h localhost -U postgres -d email_integration
```

### Redis Connection Error
```bash
# Check if Redis is running
docker ps | grep redis

# Test connection
redis-cli ping
```

### Migration Error
```bash
# Reset database (WARNING: This will delete all data)
alembic downgrade base
alembic upgrade head
```

### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>
```

---

## Next Steps

1. Read the [API Documentation](docs/API_DOCUMENTATION.md)
2. Review the [Architecture Documentation](docs/ARCHITECTURE.md)
3. Check out the [AWS Infrastructure Guide](docs/AWS_INFRASTRUCTURE.md)
4. Contribute: Read [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Support

- **Issues**: Create an issue on GitHub
- **Questions**: Start a discussion on GitHub
- **Email**: support@yourcompany.com

---

## Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [OAuth 2.0 Guide](https://oauth.net/2/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Docker Documentation](https://docs.docker.com/)
