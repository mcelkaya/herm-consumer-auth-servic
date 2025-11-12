.PHONY: help install dev test test-cov clean docker-build docker-up docker-down migrate-up migrate-down lint format

help:
	@echo "Available commands:"
	@echo "  install       - Install dependencies"
	@echo "  dev          - Run development server"
	@echo "  test         - Run tests"
	@echo "  test-cov     - Run tests with coverage"
	@echo "  clean        - Clean up generated files"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-up    - Start Docker containers"
	@echo "  docker-down  - Stop Docker containers"
	@echo "  migrate-up   - Run database migrations"
	@echo "  migrate-down - Rollback last migration"
	@echo "  lint         - Run linting"
	@echo "  format       - Format code"

install:
	pip install -r requirements.txt

dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

migrate-up:
	alembic upgrade head

migrate-down:
	alembic downgrade -1

migrate-create:
	@read -p "Enter migration message: " msg; \
	alembic revision --autogenerate -m "$$msg"

lint:
	flake8 app tests --max-line-length=100
	black --check app tests

format:
	black app tests
	isort app tests

shell:
	python -i -c "from app.main import app; from app.db.session import AsyncSessionLocal"
