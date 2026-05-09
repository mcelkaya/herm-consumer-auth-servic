# URL Migration: herm-consumer-auth-service

## Hedef URL Yapısı

```
GET  /herm-auth/v1/public/health              ← health check (root'tan taşındı)
POST /herm-auth/v1/public/auth/signup         ← no auth
POST /herm-auth/v1/public/auth/login          ← no auth
POST /herm-auth/v1/public/auth/forgot-password
POST /herm-auth/v1/public/auth/reset-password
POST /herm-auth/v1/public/auth/verify-email
GET  /herm-auth/v1/pii/auth/me               ← JWT required
POST /herm-auth/v1/pii/auth/refresh          ← JWT / HttpOnly cookie
POST /herm-auth/v1/pii/auth/logout           ← JWT required
POST /herm-auth/v1/pii/auth/logout-all       ← JWT required
POST /herm-auth/v1/pii/auth/resend-verification  ← JWT required
POST /herm-auth/v1/admin/auth/login          ← admin only
POST /herm-auth/v1/admin/auth/refresh        ← admin only
POST /herm-auth/v1/admin/auth/logout         ← admin only
GET  /herm-auth/v1/admin/auth/me             ← admin only
```

## Before → After Tam Mapping

| Kategori | ÖNCE | SONRA |
|----------|------|-------|
| Health   | `GET /herm-auth/health` | `GET /herm-auth/v1/public/health` |
| Public   | `POST /herm-auth/api/v1/auth/signup` | `POST /herm-auth/v1/public/auth/signup` |
| Public   | `POST /herm-auth/api/v1/auth/login` | `POST /herm-auth/v1/public/auth/login` |
| Public   | `POST /herm-auth/api/v1/auth/forgot-password` | `POST /herm-auth/v1/public/auth/forgot-password` |
| Public   | `POST /herm-auth/api/v1/auth/reset-password` | `POST /herm-auth/v1/public/auth/reset-password` |
| Public   | `POST /herm-auth/api/v1/auth/verify-email` | `POST /herm-auth/v1/public/auth/verify-email` |
| PII      | `GET /herm-auth/api/v1/auth/me` | `GET /herm-auth/v1/pii/auth/me` |
| PII      | `POST /herm-auth/api/v1/auth/refresh` | `POST /herm-auth/v1/pii/auth/refresh` |
| PII      | `POST /herm-auth/api/v1/auth/logout` | `POST /herm-auth/v1/pii/auth/logout` |
| PII      | `POST /herm-auth/api/v1/auth/logout-all` | `POST /herm-auth/v1/pii/auth/logout-all` |
| PII      | `POST /herm-auth/api/v1/auth/resend-verification` | `POST /herm-auth/v1/pii/auth/resend-verification` |
| Admin    | `POST /herm-auth/api/v1/admin/auth/login` | `POST /herm-auth/v1/admin/auth/login` |
| Admin    | `POST /herm-auth/api/v1/admin/auth/refresh` | `POST /herm-auth/v1/admin/auth/refresh` |
| Admin    | `POST /herm-auth/api/v1/admin/auth/logout` | `POST /herm-auth/v1/admin/auth/logout` |
| Admin    | `GET /herm-auth/api/v1/admin/auth/me` | `GET /herm-auth/v1/admin/auth/me` |

---

## PHASE 0 — Before Test (Migration Öncesi Doğrulama)

> **Amaç:** Mevcut URL'lerin çalıştığını belgele. Migration sonrası bu testler yeni URL'leri doğrular.
> Migration yapılmadan önce bu dosyayı oluştur, çalıştır → hepsi PASS olmalı (mevcut durum).
> Migration sonrası testler güncellenerek yeni URL'ler doğrulanır.

- [ ] `tests/integration/test_url_migration.py` oluştur
  - Mevcut path'lerin 200/201/422 döndürdüğünü doğrula
  - Yeni path'lerin (henüz tanımsız) 404 döndürdüğünü doğrula
  - Dosya: `herm-consumer-auth-service/tests/integration/test_url_migration.py`

---

## PHASE 1 — herm-consumer-auth-service (Backend)

### 1.1 Router Yeniden Yapılandırma

- [ ] **YENİ:** `app/api/v1/public_auth.py` oluştur
  - Router prefix: `/public/auth`
  - Taşınacak endpoint'ler: `signup`, `login`, `forgot-password`, `reset-password`, `verify-email`
  - `auth.py`'deki bu endpoint'leri buraya taşı

- [ ] **YENİ:** `app/api/v1/pii_auth.py` oluştur
  - Router prefix: `/pii/auth`
  - Taşınacak endpoint'ler: `me`, `refresh`, `logout`, `logout-all`, `resend-verification`
  - `auth.py`'deki bu endpoint'leri buraya taşı

- [ ] `app/api/v1/auth.py` sil (içerik 2 yeni dosyaya taşındı)

- [ ] `app/api/v1/admin_auth.py` — prefix değişikliği yok, `main.py`'deki include prefix değişince otomatik güncellenir

### 1.2 main.py Güncelleme

- [ ] `app/main.py` — router include'ları güncelle:
  ```python
  # ÖNCE:
  app.include_router(auth.router, prefix="/herm-auth/api/v1")
  app.include_router(admin_auth.router, prefix="/herm-auth/api/v1")

  # SONRA:
  app.include_router(public_auth.router, prefix="/herm-auth/v1")
  app.include_router(pii_auth.router, prefix="/herm-auth/v1")
  app.include_router(admin_auth.router, prefix="/herm-auth/v1")
  ```

- [ ] `app/main.py` — health check path'i güncelle:
  ```python
  # ÖNCE:
  @app.get("/herm-auth/health", ...)

  # SONRA:
  @app.get("/herm-auth/v1/public/health", ...)
  ```

### 1.3 Test Güncellemeleri (Auth Service)

- [ ] `tests/integration/test_auth_api.py` — tüm path'leri güncelle:
  - `/api/v1/auth/signup` → `/herm-auth/v1/public/auth/signup`
  - `/api/v1/auth/login` → `/herm-auth/v1/public/auth/login`
  - `/api/v1/auth/me` → `/herm-auth/v1/pii/auth/me`
  - `/api/v1/auth/refresh` → `/herm-auth/v1/pii/auth/refresh`
  - `/api/v1/auth/logout` → `/herm-auth/v1/pii/auth/logout`
  - `/api/v1/auth/logout-all` → `/herm-auth/v1/pii/auth/logout-all`
  - `/api/v1/auth/resend-verification` → `/herm-auth/v1/pii/auth/resend-verification`

- [ ] `tests/integration/test_password_reset_api.py` — path'leri güncelle:
  - `/api/v1/auth/forgot-password` → `/herm-auth/v1/public/auth/forgot-password`
  - `/api/v1/auth/reset-password` → `/herm-auth/v1/public/auth/reset-password`
  - `/api/v1/auth/verify-email` → `/herm-auth/v1/public/auth/verify-email`

- [ ] `tests/integration/test_admin_auth_api.py` — path'leri güncelle:
  - `/api/v1/admin/auth/login` → `/herm-auth/v1/admin/auth/login`
  - `/api/v1/admin/auth/refresh` → `/herm-auth/v1/admin/auth/refresh`
  - `/api/v1/admin/auth/logout` → `/herm-auth/v1/admin/auth/logout`
  - `/api/v1/admin/auth/me` → `/herm-auth/v1/admin/auth/me`

- [ ] `tests/integration/test_url_migration.py` — Phase 0'da oluşturuldu, yeni URL'leri doğrulayacak şekilde güncelle (artık yeni path'ler 200 dönmeli, eskiler 404 dönmeli)

### 1.4 Test Çalıştır

- [ ] `pytest tests/integration/ -v` — tüm integration testler pass

---

## PHASE 2 — herm-infra (Local Ortam)

- [ ] `docker-compose.yml` — auth service healthcheck path güncelle:
  ```yaml
  # ÖNCE:
  test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/herm-auth/health')"]

  # SONRA:
  test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/herm-auth/v1/public/health')"]
  ```

- [ ] `env/auth-service.env` — değiştirilecek env var yoksa geç (bağımlı URL'leri içermez)

---

## PHASE 3 — hermConsumer (Next.js SPA)

### 3.1 API Client Endpoint Güncellemeleri

- [ ] `apps/web/lib/api/authClient.ts` — tüm endpoint path'lerini güncelle:
  - `'/auth/login'` → `'/public/auth/login'`
  - `'/auth/signup'` → `'/public/auth/signup'`
  - `'/auth/me'` → `'/pii/auth/me'`
  - `'/auth/verify-email'` → `'/public/auth/verify-email'`
  - `'/auth/resend-verification'` → `'/pii/auth/resend-verification'`
  - `'/auth/forgot-password'` → `'/public/auth/forgot-password'`
  - `'/auth/reset-password'` → `'/public/auth/reset-password'`
  - `healthCheck()` içindeki hardcoded replace:
    ```ts
    // ÖNCE:
    this.baseURL.replace('/herm-auth/api/v1', '/herm-auth/health')
    // SONRA:
    this.baseURL.replace('/herm-auth/v1', '/herm-auth/v1/public/health')
    ```

- [ ] `apps/web/lib/api/tokenRefresh.ts` — refresh endpoint güncelle:
  - `/auth/refresh` içeren URL → `/pii/auth/refresh`
  - `NEXT_PUBLIC_AUTH_SERVICE_URL + NEXT_PUBLIC_AUTH_SERVICE_PATH + '/auth/refresh'` → `+ '/pii/auth/refresh'`

### 3.2 Config Güncellemeleri

- [ ] `apps/web/lib/config/api.config.ts` — fallback URL'leri güncelle:
  - `'https://beta-api.herm.io/herm-auth/api/v1'` → `'https://beta-api.herm.io/herm-auth/v1'`
  (3 yerde — development, staging, production konfigürasyonları)

### 3.3 Deploy Workflow Güncellemeleri

- [ ] `.github/workflows/deploy-production.yml`:
  ```yaml
  # ÖNCE:
  PROD_AUTH_SERVICE_PATH: '/herm-auth/api/v1'
  # SONRA:
  PROD_AUTH_SERVICE_PATH: '/herm-auth/v1'
  ```

- [ ] `.github/workflows/deploy-staging.yml` — aynı güncelleme (varsa)

---

## PHASE 4 — hermMinistry (Admin Frontend)

### 4.1 Base URL Güncelleme

- [ ] `frontend/lib/api/client.ts` — AUTH_SERVICE_URL fallback güncelle:
  ```ts
  // ÖNCE:
  const AUTH_SERVICE_URL = process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'https://api.herm.io/herm-auth/api/v1';
  // SONRA:
  const AUTH_SERVICE_URL = process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'https://api.herm.io/herm-auth/v1';
  ```

- [ ] `frontend/lib/api/auth.ts` — endpoint path'leri güncelle:
  - `'/admin/auth/login'` → `'/admin/auth/login'` (**değişmez** — admin kategorisi aynı kalıyor)
  - `'/admin/auth/refresh'` → `'/admin/auth/refresh'` (**değişmez**)
  - `'/admin/auth/logout'` → `'/admin/auth/logout'` (**değişmez**)
  - `'/admin/auth/me'` → `'/admin/auth/me'` (**değişmez**)
  - **NOT:** hermMinistry'de yalnızca base URL (`api/v1` → `v1`) değişiyor, relative path'ler aynı kalıyor.

### 4.2 Deploy Workflow Güncellemesi

- [ ] `.github/workflows/deploy-ministry.yml` — `MINISTRY_PROD_AUTH_SERVICE_URL` secret:
  - Bu secret GitHub Secrets'ta saklanıyor (`secrets.MINISTRY_PROD_AUTH_SERVICE_URL`)
  - Secret değerini `https://api.herm.io/herm-auth/v1` olarak güncelle (GitHub → Secrets & Variables → Actions)
  - **NOT:** Bu manuel adım, workflow dosyası değil.

---

## PHASE 5 — hermExtension

- [ ] hermExtension auth çağrıları kontrol et:
  - `find hermExtension/src -type f \( -name '*.ts' -o -name '*.tsx' \) | xargs grep -l 'auth\|herm-auth' 2>/dev/null`
  - Sonuç boş geldi — güncelleme gerekmeyebilir, çift kontrol et

---

## PHASE 6 — hermioBrand

- [ ] hermioBrand auth çağrıları kontrol et:
  - `find hermioBrand/src -type f \( -name '*.ts' -o -name '*.tsx' \) | xargs grep -l 'herm-auth\|auth/login\|auth/signup' 2>/dev/null`
  - Sonuç boş geldi — güncelleme gerekmeyebilir, çift kontrol et

---

## PHASE 7 — herm-stack-aws (Production ALB / ECS)

- [ ] `prod/main.tf` — ALB listener rule / target group path pattern kontrol et:
  - `herm-auth/api/v1` → `herm-auth/v1` path match kuralları varsa güncelle
  - `grep -n 'herm-auth' prod/main.tf` ile kontrol et

- [ ] ECS Task Definition (`ecs-task-definitions/production.json`):
  - Healthcheck URL var mı kontrol et → varsa `/herm-auth/health` → `/herm-auth/v1/public/health`
  - Şu an production.json'da healthcheck tanımlanmamış (ECS task definition'da değil, ALB target group'ta) — ALB'yi kontrol et

---

## PHASE 8 — Son Doğrulama

- [ ] Auth service tüm testler pass: `pytest tests/ -v`
- [ ] Local docker-compose'da auth servis healthcheck başarılı:
  ```bash
  curl http://localhost:8001/herm-auth/v1/public/health
  ```
- [ ] hermConsumer local'de çalışıyor — login/signup/me flow test et
- [ ] hermMinistry local'de çalışıyor — admin login test et
- [ ] Tüm eski URL'ler (`/herm-auth/api/v1/*`) 404 dönüyor (geriye dönük uyumluluk yok)

---

## Bağımlılık Sırası

```
Phase 0 (before tests)
    ↓
Phase 1 (backend — auth service)
    ↓
Phase 1.4 (testler pass)
    ↓
Phase 2 (infra)    Phase 3 (hermConsumer)    Phase 4 (hermMinistry)    Phase 5-6 (Extension/Brand)
    ↓                      ↓                          ↓
                      Phase 7 (AWS)
                           ↓
                      Phase 8 (son doğrulama)
```

## Özet: Değişen Dosyalar

### herm-consumer-auth-service
| Dosya | Değişiklik |
|-------|-----------|
| `app/main.py` | Router prefix `api/v1` → `v1`, health path güncelle |
| `app/api/v1/auth.py` | Sil — içerik 2 yeni dosyaya taşındı |
| `app/api/v1/public_auth.py` | **YENİ** — public endpoints |
| `app/api/v1/pii_auth.py` | **YENİ** — PII endpoints (JWT required) |
| `app/api/v1/admin_auth.py` | Prefix değişmez, main.py'deki include değişiyor |
| `tests/integration/test_auth_api.py` | Tüm path'ler güncellendi |
| `tests/integration/test_password_reset_api.py` | Tüm path'ler güncellendi |
| `tests/integration/test_admin_auth_api.py` | Tüm path'ler güncellendi |
| `tests/integration/test_url_migration.py` | **YENİ** — migration doğrulama |

### herm-infra
| Dosya | Değişiklik |
|-------|-----------|
| `docker-compose.yml` | Healthcheck path güncellendi |

### hermConsumer
| Dosya | Değişiklik |
|-------|-----------|
| `apps/web/lib/api/authClient.ts` | Tüm endpoint relative path'ler güncellendi |
| `apps/web/lib/api/tokenRefresh.ts` | `/auth/refresh` → `/pii/auth/refresh` |
| `apps/web/lib/config/api.config.ts` | Fallback URL'ler güncellendi (`api/v1` → `v1`) |
| `.github/workflows/deploy-production.yml` | `PROD_AUTH_SERVICE_PATH` güncellendi |
| `.github/workflows/deploy-staging.yml` | `PROD_AUTH_SERVICE_PATH` güncellendi (varsa) |

### hermMinistry
| Dosya | Değişiklik |
|-------|-----------|
| `frontend/lib/api/client.ts` | `AUTH_SERVICE_URL` fallback güncellendi |
| GitHub Secret | `MINISTRY_PROD_AUTH_SERVICE_URL` — manuel güncelleme |
