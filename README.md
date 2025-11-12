# Email Integration Service

A production-ready microservice for managing consumer email integrations with Gmail, Outlook, and Yahoo.

## 🏗️ Architecture

- **Backend**: Python with FastAPI
- **ORM**: SQLAlchemy (async) with Alembic migrations
- **Database**: PostgreSQL
- **Cache**: Redis
- **Container**: Docker
- **CI/CD**: GitHub Actions
- **Infrastructure**: AWS (ECS, ECR, RDS)
- **Development**: TDD approach with pytest

## 📋 Features

- ✅ User authentication (JWT-based)
- ✅ Email provider OAuth integration (Gmail, Outlook, Yahoo)
- ✅ Connect and manage multiple email accounts
- ✅ Secure token storage
- ✅ RESTful API with OpenAPI documentation
- ✅ Comprehensive test coverage
- ✅ Database migrations with Alembic
- ✅ Docker containerization
- ✅ CI/CD pipeline with GitHub Actions

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker and Docker Compose (for containerized setup)

### Environment Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd email-integration-service
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

### Running the Application

#### Local Development

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Docker Compose

```bash
docker-compose up -d
```

Access the API at: http://localhost:8000

API Documentation: http://localhost:8000/docs

## 🧪 Testing

### Run all tests
```bash
pytest
```

### Run with coverage
```bash
pytest --cov=app --cov-report=html
```

### Run specific test types
```bash
# Unit tests only
pytest tests/unit -v

# Integration tests only
pytest tests/integration -v
```

## 📁 Project Structure

```
email-integration-service/
├── app/
│   ├── api/
│   │   ├── dependencies.py      # API dependencies
│   │   └── v1/
│   │       ├── auth.py          # Authentication endpoints
│   │       ├── connected_apps.py # Connected apps endpoints
│   │       └── oauth.py         # OAuth callback endpoints
│   ├── core/
│   │   ├── config.py            # Application configuration
│   │   └── security.py          # Security utilities
│   ├── db/
│   │   └── session.py           # Database session management
│   ├── models/
│   │   ├── user.py              # User model
│   │   └── connected_app.py    # Connected app model
│   ├── repositories/
│   │   ├── user_repository.py   # User data access
│   │   └── connected_app_repository.py
│   ├── schemas/
│   │   └── user.py              # Pydantic schemas
│   ├── services/
│   │   ├── user_service.py      # User business logic
│   │   ├── connected_app_service.py
│   │   └── oauth_service.py     # OAuth integration
│   └── main.py                  # FastAPI application
├── tests/
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── conftest.py              # Test fixtures
├── alembic/
│   ├── versions/                # Database migrations
│   └── env.py                   # Alembic configuration
├── .github/
│   └── workflows/
│       └── ci-cd.yml            # CI/CD pipeline
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── pytest.ini
└── README.md
```

## 🔐 API Endpoints

### Authentication

- `POST /api/v1/auth/signup` - Register new user
- `POST /api/v1/auth/login` - Login user
- `GET /api/v1/auth/me` - Get current user info

### Connected Apps

- `POST /api/v1/connected-apps` - Connect email provider
- `GET /api/v1/connected-apps` - List connected apps
- `DELETE /api/v1/connected-apps/{app_id}` - Delete connected app

### OAuth

- `GET /api/v1/oauth/google/authorize` - Get Google OAuth URL
- `GET /api/v1/oauth/google/callback` - Google OAuth callback
- `GET /api/v1/oauth/microsoft/authorize` - Get Microsoft OAuth URL
- `GET /api/v1/oauth/microsoft/callback` - Microsoft OAuth callback
- `GET /api/v1/oauth/yahoo/authorize` - Get Yahoo OAuth URL
- `GET /api/v1/oauth/yahoo/callback` - Yahoo OAuth callback

## 🔄 Database Migrations

### Create a new migration
```bash
alembic revision --autogenerate -m "Description"
```

### Apply migrations
```bash
alembic upgrade head
```

### Rollback migration
```bash
alembic downgrade -1
```

## 🐳 Docker

### Build image
```bash
docker build -t email-integration-service .
```

### Run container
```bash
docker run -p 8000:8000 --env-file .env email-integration-service
```

## 🚢 Deployment

### AWS ECS Deployment

The application is automatically deployed to AWS ECS through GitHub Actions:

1. **Develop branch** → Staging environment
2. **Main branch** → Production environment

### Manual Deployment

```bash
# Configure AWS CLI
aws configure

# Build and push to ECR
docker build -t email-integration-service .
docker tag email-integration-service:latest ${ECR_REGISTRY}/email-integration-service:latest
docker push ${ECR_REGISTRY}/email-integration-service:latest

# Update ECS service
aws ecs update-service \
  --cluster email-integration-cluster \
  --service email-integration-service \
  --force-new-deployment
```

## 🔒 Security

- JWT-based authentication
- Password hashing with bcrypt
- Secure token storage
- OAuth 2.0 integration
- Environment-based configuration
- SQL injection prevention (SQLAlchemy ORM)
- CORS configuration
- Request validation (Pydantic)

## 📊 Monitoring

- Health check endpoint: `/health`
- Application logs
- Database connection pooling
- Redis caching

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

## 👥 Authors

- Your Team

## 🆘 Support

For support, email support@yourcompany.com or create an issue in the repository.

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [OAuth 2.0 Specification](https://oauth.net/2/)
