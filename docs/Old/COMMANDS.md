# Email Integration Service - Commands Cheat Sheet

## 🚀 Quick Start Commands

### Initial Setup
```bash
# Navigate to project
cd email-integration-service

# Copy environment template
cp .env.example .env

# Start all services
docker-compose up -d

# Run migrations
docker-compose exec app alembic upgrade head

# Check health
curl http://localhost:8000/health
```

---

## 🐳 Docker Commands

### Container Management
```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart specific service
docker-compose restart app

# View logs
docker-compose logs -f app

# Access app container
docker-compose exec app bash

# Remove all containers and volumes
docker-compose down -v
```

### Build Commands
```bash
# Build images
docker-compose build

# Build without cache
docker-compose build --no-cache

# Build specific service
docker-compose build app
```

---

## 🗄️ Database Commands

### Migrations
```bash
# Create new migration
alembic revision --autogenerate -m "Description of changes"

# Apply all migrations
alembic upgrade head

# Rollback last migration
alembic downgrade -1

# Rollback to specific version
alembic downgrade <revision_id>

# Show current version
alembic current

# Show migration history
alembic history

# Show SQL without executing
alembic upgrade head --sql
```

### Database Access
```bash
# Connect to database
docker-compose exec db psql -U postgres -d email_integration

# Run SQL file
docker-compose exec db psql -U postgres -d email_integration -f /path/to/file.sql

# Backup database
docker-compose exec db pg_dump -U postgres email_integration > backup.sql

# Restore database
docker-compose exec -T db psql -U postgres email_integration < backup.sql
```

---

## 🧪 Testing Commands

### Run Tests
```bash
# All tests
pytest

# With verbose output
pytest -v

# Specific test file
pytest tests/unit/test_user_service.py

# Specific test function
pytest tests/unit/test_user_service.py::test_user_signup_success

# Run only unit tests
pytest tests/unit -v

# Run only integration tests
pytest tests/integration -v

# Run with markers
pytest -m unit
pytest -m integration
```

### Coverage
```bash
# Run with coverage
pytest --cov=app

# Generate HTML coverage report
pytest --cov=app --cov-report=html

# View coverage report
open htmlcov/index.html

# Generate XML coverage report (for CI)
pytest --cov=app --cov-report=xml

# Show missing lines
pytest --cov=app --cov-report=term-missing
```

### Using Docker
```bash
# Run tests in Docker
docker-compose exec app pytest

# Run with coverage
docker-compose exec app pytest --cov=app --cov-report=html

# Run specific tests
docker-compose exec app pytest tests/unit -v
```

---

## 📝 Development Commands

### Run Application
```bash
# Local development
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# With specific environment
ENVIRONMENT=development uvicorn app.main:app --reload

# Docker
docker-compose up app
```

### Code Quality
```bash
# Format code with black
black app tests

# Check formatting
black --check app tests

# Sort imports
isort app tests

# Lint with flake8
flake8 app tests --max-line-length=100

# Run all quality checks
black app tests && isort app tests && flake8 app tests
```

### Using Makefile
```bash
make install       # Install dependencies
make dev           # Run development server
make test          # Run tests
make test-cov      # Run tests with coverage
make lint          # Run linting
make format        # Format code
make clean         # Clean up files
make docker-up     # Start Docker services
make docker-down   # Stop Docker services
make migrate-up    # Run migrations
make migrate-down  # Rollback migration
```

---

## 🔐 Environment Management

### Environment Variables
```bash
# View current environment
env | grep -E "DATABASE|REDIS|SECRET"

# Set environment variable
export DATABASE_URL="postgresql+asyncpg://user:pass@localhost/db"

# Load from .env file
source .env

# Check specific variable
echo $SECRET_KEY
```

---

## 📊 Monitoring & Debugging

### Logs
```bash
# View application logs
docker-compose logs -f app

# View database logs
docker-compose logs -f db

# View Redis logs
docker-compose logs -f redis

# View last 100 lines
docker-compose logs --tail=100 app

# Follow logs from timestamp
docker-compose logs --since="2024-01-01T00:00:00Z" -f app
```

### Health Checks
```bash
# Application health
curl http://localhost:8000/health

# Database connection
docker-compose exec db pg_isready -U postgres

# Redis connection
docker-compose exec redis redis-cli ping
```

### Resource Usage
```bash
# Container stats
docker stats

# Specific container
docker stats email-integration-api

# Memory usage
docker-compose exec app free -h

# Disk usage
docker-compose exec app df -h
```

---

## 🌐 API Testing Commands

### Authentication
```bash
# Signup
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'

# Get current user
curl -X GET http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer <token>"
```

### Connected Apps
```bash
# List connected apps
curl -X GET http://localhost:8000/api/v1/connected-apps \
  -H "Authorization: Bearer <token>"

# Connect app
curl -X POST http://localhost:8000/api/v1/connected-apps \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "gmail",
    "provider_email": "user@gmail.com",
    "access_token": "token",
    "refresh_token": "refresh"
  }'

# Delete connected app
curl -X DELETE http://localhost:8000/api/v1/connected-apps/<app_id> \
  -H "Authorization: Bearer <token>"
```

### OAuth
```bash
# Get Google OAuth URL
curl -X GET http://localhost:8000/api/v1/oauth/google/authorize

# Handle callback
curl -X GET "http://localhost:8000/api/v1/oauth/google/callback?code=<code>" \
  -H "Authorization: Bearer <token>"
```

---

## 🚀 Deployment Commands

### AWS ECR
```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com

# Build image
docker build -t email-integration-service .

# Tag image
docker tag email-integration-service:latest \
  <account>.dkr.ecr.us-east-1.amazonaws.com/email-integration-service:latest

# Push image
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/email-integration-service:latest
```

### AWS ECS
```bash
# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Update service (force new deployment)
aws ecs update-service \
  --cluster email-integration-cluster \
  --service email-integration-service \
  --force-new-deployment

# View service status
aws ecs describe-services \
  --cluster email-integration-cluster \
  --services email-integration-service

# View task logs
aws logs tail /ecs/email-integration-service --follow
```

---

## 🛠️ Troubleshooting Commands

### Port Issues
```bash
# Find process using port
lsof -i :8000

# Kill process
kill -9 <PID>

# Alternative (macOS)
sudo lsof -t -i :8000 | xargs kill -9
```

### Database Issues
```bash
# Reset database
docker-compose down -v
docker-compose up -d db
alembic upgrade head

# Check connections
docker-compose exec db psql -U postgres -c "SELECT * FROM pg_stat_activity;"

# Kill connections
docker-compose exec db psql -U postgres -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='email_integration';"
```

### Redis Issues
```bash
# Flush all data
docker-compose exec redis redis-cli FLUSHALL

# Check memory usage
docker-compose exec redis redis-cli INFO memory

# Monitor commands
docker-compose exec redis redis-cli MONITOR
```

### Application Issues
```bash
# Check Python version
python --version

# Check installed packages
pip list

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Clear Python cache
find . -type d -name __pycache__ -exec rm -rf {} +
find . -type f -name "*.pyc" -delete
```

---

## 🔄 Git Commands

### Branch Management
```bash
# Create feature branch
git checkout -b feature/new-feature

# Push to remote
git push -u origin feature/new-feature

# Merge to main
git checkout main
git merge feature/new-feature
git push origin main
```

### Deployment Triggers
```bash
# Deploy to staging (develop branch)
git checkout develop
git push origin develop

# Deploy to production (main branch)
git checkout main
git merge develop
git push origin main
```

---

## 📦 Package Management

### Python Dependencies
```bash
# Install all dependencies
pip install -r requirements.txt

# Install in editable mode
pip install -e .

# Update specific package
pip install --upgrade fastapi

# Generate requirements
pip freeze > requirements.txt

# Install development dependencies
pip install pytest black flake8 isort
```

---

## 🎯 Quick Reference

### Most Used Commands
```bash
# Start development
docker-compose up -d && docker-compose logs -f app

# Run tests
pytest -v --cov=app

# Run migrations
alembic upgrade head

# Format code
black app tests && isort app tests

# Check API
curl http://localhost:8000/health

# View logs
docker-compose logs -f app

# Access container
docker-compose exec app bash

# Stop everything
docker-compose down
```

### One-Line Setup
```bash
cp .env.example .env && docker-compose up -d && sleep 5 && docker-compose exec app alembic upgrade head && curl http://localhost:8000/health
```

---

## 📚 Additional Resources

- API Documentation: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Project README: README.md
- Quick Start: docs/QUICK_START.md
- API Docs: docs/API_DOCUMENTATION.md
