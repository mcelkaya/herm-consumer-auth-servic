# Email Integration Service - Proje Yapısı

## 📁 Tam Klasör Yapısı

```
email-integration-service/
│
├── 📄 .env.example                    # Örnek environment değişkenleri
├── 📄 .gitignore                      # Git ignore kuralları
├── 📄 COMMANDS.md                     # Komut referansı
├── 📄 Dockerfile                      # Production Docker image
├── 📄 Makefile                        # Kısayol komutlar
├── 📄 PROJECT_SUMMARY.md              # Proje özeti
├── 📄 README.md                       # Ana dokümantasyon
├── 📄 alembic.ini                     # Alembic konfigürasyonu
├── 📄 docker-compose.yml              # Local development stack
├── 📄 pytest.ini                      # Test konfigürasyonu
├── 📄 requirements.txt                # Python bağımlılıkları
├── 📄 task-definition.json            # AWS ECS task definition
│
├── 📁 .github/
│   └── workflows/
│       └── ci-cd.yml                  # GitHub Actions CI/CD pipeline
│
├── 📁 alembic/                        # Database migration yönetimi
│   ├── env.py                         # Alembic environment
│   ├── script.py.mako                 # Migration template
│   └── versions/
│       └── 001_initial_migration.py   # İlk migration
│
├── 📁 app/                            # Ana uygulama kodu
│   ├── __init__.py
│   ├── main.py                        # FastAPI uygulaması
│   │
│   ├── 📁 api/                        # API katmanı
│   │   ├── __init__.py
│   │   ├── dependencies.py            # Auth bağımlılıkları
│   │   └── v1/                        # API v1 endpoints
│   │       ├── __init__.py
│   │       ├── auth.py                # Authentication endpoints
│   │       ├── connected_apps.py      # Connected apps endpoints
│   │       └── oauth.py               # OAuth endpoints
│   │
│   ├── 📁 core/                       # Temel yapılandırma
│   │   ├── __init__.py
│   │   ├── config.py                  # Uygulama ayarları
│   │   └── security.py                # JWT & şifreleme
│   │
│   ├── 📁 db/                         # Database yönetimi
│   │   ├── __init__.py
│   │   └── session.py                 # Database session
│   │
│   ├── 📁 models/                     # SQLAlchemy modelleri
│   │   ├── __init__.py
│   │   ├── connected_app.py           # ConnectedApp modeli
│   │   └── user.py                    # User modeli
│   │
│   ├── 📁 repositories/               # Data access katmanı
│   │   ├── __init__.py
│   │   ├── connected_app_repository.py
│   │   └── user_repository.py
│   │
│   ├── 📁 schemas/                    # Pydantic şemaları
│   │   ├── __init__.py
│   │   └── user.py                    # Request/Response şemaları
│   │
│   └── 📁 services/                   # Business logic katmanı
│       ├── __init__.py
│       ├── connected_app_service.py   # Connected app business logic
│       ├── oauth_service.py           # OAuth integration logic
│       └── user_service.py            # User business logic
│
├── 📁 docs/                           # Dokümantasyon
│   ├── API_DOCUMENTATION.md           # Detaylı API dokümantasyonu
│   ├── AWS_INFRASTRUCTURE.md          # AWS deployment rehberi
│   └── QUICK_START.md                 # Hızlı başlangıç rehberi
│
└── 📁 tests/                          # Test dosyaları
    ├── __init__.py
    ├── conftest.py                    # Test fixtures
    │
    ├── 📁 integration/                # Integration testleri
    │   ├── __init__.py
    │   ├── test_auth_api.py           # Auth API testleri (6 test)
    │   └── test_connected_apps_api.py # Connected apps testleri (6 test)
    │
    └── 📁 unit/                       # Unit testleri
        ├── __init__.py
        └── test_user_service.py       # User service testleri (5 test)
```

## 📊 İstatistikler

- **Toplam Python Dosyası**: 34
- **Toplam Dosya**: 51
- **Klasör Sayısı**: 18
- **Test Sayısı**: 17 (5 unit + 12 integration)
- **API Endpoint**: 12
- **Database Model**: 2
- **Service**: 3

## 🗂️ Katman Yapısı

### 1️⃣ API Katmanı (`app/api/`)
- HTTP request/response handling
- Request validation
- Authentication kontrolü
- 12 endpoint

### 2️⃣ Service Katmanı (`app/services/`)
- Business logic
- Transaction yönetimi
- OAuth akışları
- Veri validasyonu

### 3️⃣ Repository Katmanı (`app/repositories/`)
- Database CRUD operasyonları
- Query optimizasyonu
- Data access abstraction

### 4️⃣ Model Katmanı (`app/models/`)
- SQLAlchemy ORM modelleri
- Database schema tanımları
- İlişki yönetimi

### 5️⃣ Schema Katmanı (`app/schemas/`)
- Pydantic validation
- Request/Response modelleri
- Type safety

## 🔐 Güvenlik Yapısı

```
app/core/
├── config.py          # Environment variables
└── security.py        # JWT, password hashing

app/api/
└── dependencies.py    # Auth middleware
```

## 🧪 Test Yapısı

```
tests/
├── conftest.py                 # Test fixtures & setup
├── unit/                       # Birim testleri
│   └── test_user_service.py
└── integration/                # Entegrasyon testleri
    ├── test_auth_api.py
    └── test_connected_apps_api.py
```

## 🚀 Deployment Dosyaları

```
.github/workflows/ci-cd.yml    # CI/CD pipeline
Dockerfile                     # Production image
docker-compose.yml             # Local development
task-definition.json           # AWS ECS task
```

## 📚 Dokümantasyon Dosyaları

```
README.md                      # Ana dokümantasyon
PROJECT_SUMMARY.md             # Proje özeti
COMMANDS.md                    # Komut referansı
docs/
├── API_DOCUMENTATION.md       # API detayları
├── AWS_INFRASTRUCTURE.md      # Infrastructure guide
└── QUICK_START.md            # 5 dakikada başlangıç
```

## 🔧 Konfigürasyon Dosyaları

```
.env.example                   # Environment şablonu
.gitignore                     # Git ignore
alembic.ini                    # DB migration config
pytest.ini                     # Test config
requirements.txt               # Dependencies
Makefile                       # Shortcut commands
```

## 📦 İndirme Sonrası

Projeyi indirdikten sonra:

1. **Ortam Hazırlığı**
   ```bash
   cd email-integration-service
   cp .env.example .env
   # .env dosyasını düzenle
   ```

2. **Docker ile Başlat**
   ```bash
   docker-compose up -d
   docker-compose exec app alembic upgrade head
   ```

3. **Test Et**
   ```bash
   curl http://localhost:8000/health
   open http://localhost:8000/docs
   ```

## 🎯 Önemli Dosyalar

| Dosya | Açıklama |
|-------|----------|
| `app/main.py` | FastAPI uygulaması başlangıç noktası |
| `app/core/config.py` | Tüm konfigürasyon ayarları |
| `app/core/security.py` | JWT ve şifreleme fonksiyonları |
| `alembic/versions/001_*.py` | İlk database migration |
| `docker-compose.yml` | Local development stack |
| `Dockerfile` | Production image tarifi |
| `.github/workflows/ci-cd.yml` | Otomatik deployment |

## ✅ Tüm Dosyalar Yerli Yerinde!

Her şey doğru klasör yapısında, production-ready durumda! 🚀
