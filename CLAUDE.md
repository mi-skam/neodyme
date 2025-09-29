# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Neodyme is a production-ready Python backend built with FastAPI, SQLModel, and PostgreSQL. It follows an src-layout structure with clean separation of concerns across models, repositories, routes, and core configuration.

## Development Commands

### Setup and Installation
```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Copy environment template
cp .env.example .env
```

### Package Management
```bash
# Add production dependency
uv add package-name

# Add development dependency
uv add --dev package-name

# Remove dependency
uv remove package-name

# Update dependencies
uv lock --upgrade

# Show dependency tree
uv tree
```

### Database Operations
```bash
# Run migrations
uv run alembic upgrade head

# Create new migration
uv run alembic revision --autogenerate -m "Description"

# Rollback migration
uv run alembic downgrade -1
```

### Running the Application
```bash
# Local development (SQLite)
uv run uvicorn neodyme.main:app --reload

# Docker development stack (PostgreSQL + pgAdmin)
docker-compose up -d

# Production build
docker build -t neodyme:latest .
```

### Testing
```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src --cov-report=html

# Run specific test file
uv run pytest tests/test_users.py
```

### Code Quality
```bash
# Format code
uv run ruff format .

# Lint and fix issues
uv run ruff check --fix .

# Type checking
uv run mypy src/
```

## Project Architecture

### Core Structure
- `src/neodyme/core/` - Configuration, database setup, exception handling
- `src/neodyme/models/` - SQLModel entities with Pydantic validation
- `src/neodyme/repositories/` - Data access layer with async CRUD operations
- `src/neodyme/routes/` - FastAPI route handlers
- `tests/` - Pytest test suite with async fixtures
- `alembic/` - Database migration scripts

### Key Design Patterns
- **Repository Pattern**: BaseRepository provides reusable async CRUD operations
- **Dependency Injection**: FastAPI dependencies for database sessions
- **Settings Management**: Pydantic Settings with 12-factor configuration
- **Exception Handling**: Global exception handlers with standardized responses

### Database Configuration
- SQLite for local development/testing (`sqlite+aiosqlite:///./test.db`)
- PostgreSQL for production (`postgresql+asyncpg://user:pass@host/db`)
- Automatic database switching via `DATABASE_URL` environment variable

### Package Management with uv
- **uv** as the primary package manager for fast dependency resolution
- Lockfile (`uv.lock`) ensures reproducible builds across environments
- Dependency groups for dev/test isolation
- Python version management with `.python-version`

### Testing Strategy
- In-memory SQLite database per test session
- Async test client with dependency overrides
- Comprehensive CRUD and API endpoint testing
- Type-safe fixtures and test utilities