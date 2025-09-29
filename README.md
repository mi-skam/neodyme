# Neodyme

A production-ready Python backend built with FastAPI, SQLModel, and PostgreSQL.

## Features

- **FastAPI** (v0.104+) with automatic OpenAPI documentation
- **SQLModel** (v0.0.14+) for database ORM with Pydantic v2 integration
- **Async database operations** with SQLAlchemy 2.x
- **Alembic** for database migrations
- **PostgreSQL** (production) and **SQLite** (development/testing) support
- **Docker** containerization with multi-stage builds
- **Comprehensive testing** with pytest and async fixtures
- **Type safety** with 100% type annotations
- **12-factor configuration** with Pydantic Settings

## Project Structure

```
neodyme/
├── src/neodyme/           # Source code (src-layout)
│   ├── core/              # Core configuration and database
│   ├── models/            # SQLModel database models
│   ├── repositories/      # Data access layer
│   ├── routes/            # FastAPI route handlers
│   └── main.py           # FastAPI application factory
├── tests/                 # Test suite
├── alembic/              # Database migrations
├── docker-compose.yml    # Local development stack
├── Dockerfile           # Production container
└── pyproject.toml      # Dependencies and tool configuration
```

## Quick Start

### Local Development (SQLite)

1. **Setup environment:**
   ```bash
   cp .env.example .env
   # Edit .env file with your settings
   ```

2. **Install uv (if not already installed):**
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **Install dependencies:**
   ```bash
   uv sync
   ```

4. **Run database migrations:**
   ```bash
   uv run alembic upgrade head
   ```

5. **Start the development server:**
   ```bash
   uv run uvicorn neodyme.main:app --reload
   ```

6. **Access the API:**
   - API: http://localhost:8000
   - Interactive docs: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

### Docker Development (PostgreSQL)

1. **Start the stack:**
   ```bash
   docker-compose up -d
   ```

2. **Access services:**
   - API: http://localhost:8000
   - pgAdmin: http://localhost:5050 (admin@neodyme.local / admin)

## Development Commands

### Database Migrations

```bash
# Create a new migration
uv run alembic revision --autogenerate -m "Add users table"

# Apply migrations
uv run alembic upgrade head

# Rollback migrations
uv run alembic downgrade -1
```

### Testing

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src --cov-report=html

# Run specific test file
uv run pytest tests/test_users.py

# Run tests in parallel
uv run pytest -n auto
```

### Code Quality

```bash
# Format code
uv run ruff format .

# Lint code
uv run ruff check .

# Fix linting issues
uv run ruff check --fix .

# Type checking
uv run mypy src/
```

### Development Tools

```bash
# Add a new dependency
uv add fastapi

# Add a development dependency
uv add --dev pytest

# Remove a dependency
uv remove package-name

# Update dependencies
uv lock --upgrade

# Show project info
uv tree
```

## Configuration

The application uses Pydantic Settings for 12-factor configuration. Set these environment variables:

### Required Settings

- `DATABASE_URL`: Database connection string
- `SECRET_KEY`: Secret key for JWT tokens (minimum 32 characters)

### Optional Settings

- `DEBUG`: Enable debug mode (default: false)
- `ENVIRONMENT`: Environment name (development/staging/production)
- `API_V1_PREFIX`: API version prefix (default: /api/v1)

### Database URL Examples

```bash
# SQLite (development/testing)
DATABASE_URL=sqlite+aiosqlite:///./neodyme.db

# PostgreSQL (production)
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/neodyme
```

## API Documentation

The API automatically generates OpenAPI documentation available at:

- **Swagger UI**: `/docs`
- **ReDoc**: `/redoc`
- **OpenAPI JSON**: `/openapi.json`

### Example API Usage

```bash
# Create a user
curl -X POST "http://localhost:8000/api/v1/users/" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "full_name": "John Doe",
    "password": "securepassword123"
  }'

# Get all users
curl "http://localhost:8000/api/v1/users/"

# Get a specific user
curl "http://localhost:8000/api/v1/users/1"
```

## Production Deployment

### Docker

```bash
# Build production image
docker build -t neodyme:latest .

# Run with PostgreSQL
docker run -e DATABASE_URL=postgresql+asyncpg://... neodyme:latest
```

### Security Considerations

- Set a strong `SECRET_KEY` in production
- Use PostgreSQL for production databases
- Run as non-root user (handled by Dockerfile)
- Enable HTTPS in production
- Set appropriate CORS policies

## Architecture

### Repository Pattern

The application uses the repository pattern for data access:

```python
from neodyme.repositories import user_repository
from neodyme.models import UserCreate

# Create a user
user = await user_repository.create(session, obj_in=UserCreate(...))

# Get a user
user = await user_repository.get(session, id=1)

# Update a user
updated_user = await user_repository.update(session, db_obj=user, obj_in=update_data)
```

### Database Models

SQLModel provides both Pydantic and SQLAlchemy models:

```python
from neodyme.models import User, UserCreate, UserPublic

# Database model (for SQLAlchemy)
user = User(email="test@example.com", ...)

# Input validation (for API requests)
user_data = UserCreate(email="test@example.com", ...)

# Output serialization (for API responses)
user_response = UserPublic.model_validate(user)
```

## Testing

The test suite uses pytest with async fixtures:

```python
@pytest.mark.asyncio
async def test_create_user(async_client: AsyncClient) -> None:
    response = await async_client.post("/api/v1/users/", json={...})
    assert response.status_code == 201
```

Test database is automatically created and cleaned up for each test session.

## Contributing

1. Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`
2. Install dependencies: `uv sync`
3. Set up pre-commit hooks: `uv run pre-commit install`
4. Run tests: `uv run pytest`
5. Check types: `uv run mypy src/`
6. Format code: `uv run ruff format .`

## License

This project is licensed under the MIT License.