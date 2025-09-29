---
title: "Chapter 2"
weight: 2
type: docs
---
# Chapter 2: "I Need to Store Data That Persists"

You've built an API that handles HTTP requests beautifully. But there's a problem: every time someone restarts your server, all data disappears. Your users create accounts, add content, make purchases—and poof, it's all gone.

This isn't just inconvenient; it's business-critical. Imagine telling your customers: "Sorry, our server restarted, so we lost all your data. Please recreate your account." Your company would be out of business faster than you can say "database backup."

## The Problem: Moving Beyond Toy Applications

Let me ask you a question: Have you ever tried to build a "real" application, only to realize that storing data properly is incredibly complicated?

Here's what seems like it should be simple:

```python
# What you want to do
users = []  # Store users in memory

@app.post("/users/")
def create_user(user_data):
    users.append(user_data)
    return user_data
```

But in production, this approach fails catastrophically because:

- **Data disappears on restart** - Every deployment, crash, or server restart wipes out all user data, orders, and content
- **No concurrent access** - Multiple API instances can't share the same in-memory list, leading to inconsistent data across servers
- **Memory limitations** - Your server runs out of RAM when you have more than a few thousand records
- **No data validation** - Users can send malformed data that corrupts your entire dataset
- **No relationships** - You can't link users to their orders, posts to their authors, or any complex data structures
- **No transactions** - If something goes wrong halfway through an operation, you're left with corrupted, half-updated data

The real question isn't "How do I store data?" It's "How do I store data reliably, efficiently, and safely?"

## Why Databases Are Hard (And Why They Don't Have to Be)

Traditional database programming feels like this:

```python
# Traditional database code - painful and error-prone
import sqlite3

def create_user(email, name, password):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    try:
        # Raw SQL - one typo breaks everything
        cursor.execute(
            "INSERT INTO users (email, full_name, hashed_password, created_at) VALUES (?, ?, ?, ?)",
            (email, name, hash_password(password), datetime.now())
        )
        conn.commit()
        
        # Get the created user - more raw SQL
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()
        
        return {
            'id': result[0],
            'email': result[1], 
            'full_name': result[2],
            # Hope you remember the column order!
        }
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
```

**What's wrong with this approach?**

- **SQL injection vulnerabilities** - Malicious users can destroy your database with crafted input
- **Manual connection management** - Forget to close a connection and you leak resources until your server crashes
- **No type safety** - Misspell a column name and you get runtime errors in production
- **Brittle code** - Change the database schema and you have to update SQL strings scattered throughout your codebase
- **No async support** - Each database call blocks your entire API, destroying performance
- **Manual error handling** - Forget to wrap something in try/catch and unhandled exceptions crash your server

This is why many developers avoid databases or use oversimplified solutions that don't scale.

## The SQLModel Solution: Bringing Python to Databases

What if you could work with databases using the same Python skills you already have? SQLModel makes this possible by combining:

- **Pydantic validation** - Automatic data validation using the same type hints you learned in Chapter 1
- **SQLAlchemy power** - Battle-tested database toolkit used by thousands of companies
- **Async support** - Non-blocking database operations that scale with your traffic
- **Type safety** - Catch database-related bugs at development time, not in production

But here's the key insight: SQLModel isn't just another ORM. It's designed specifically to work with FastAPI's type system, meaning your database models automatically become your API models too.

Let's see how neodyme implements this properly.

## Building Your First Database Model

### Step 1: Understanding the Foundation

Before we dive into code, let's understand what we're building. In neodyme, every database model follows a specific pattern that solves real-world problems:

```python
# From neodyme's models/user.py (simplified)
from datetime import datetime
from sqlmodel import Field, SQLModel

class UserBase(SQLModel):
    email: str = Field(unique=True, index=True, max_length=255)
    full_name: str = Field(max_length=255)
    is_active: bool = Field(default=True)

class User(UserBase, table=True):
    __tablename__ = "users"
    
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str = Field(max_length=255)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False,
        sa_column_kwargs={"onupdate": datetime.utcnow},
    )
```

**Let's break down why every piece matters:**

1. **`UserBase` with shared fields**: This contains fields that appear in multiple contexts (API requests, responses, database records). By defining them once, you prevent bugs where the API and database have different field definitions.

2. **`email: str = Field(unique=True, index=True, max_length=255)`**: 
   - `unique=True` prevents duplicate accounts and generates a database constraint that catches violations automatically
   - `index=True` creates a database index for fast email lookups (essential for login performance)
   - `max_length=255` prevents someone from submitting gigabyte-sized email strings that could crash your server

3. **`id: int | None = Field(default=None, primary_key=True)`**: 
   - `None` as default because the database generates the ID automatically
   - `primary_key=True` tells the database this field uniquely identifies each record
   - Auto-incrementing IDs prevent conflicts when multiple users sign up simultaneously

4. **Timestamp fields with `default_factory=datetime.utcnow`**:
   - `default_factory` calls the function each time, so every record gets the current timestamp
   - Using UTC prevents timezone-related bugs that occur when servers and users are in different time zones
   - `onupdate` automatically tracks when records are modified, essential for auditing and debugging

### Step 2: Creating Input and Output Models

Raw database models aren't suitable for APIs because they contain fields users shouldn't see or modify. Neodyme creates specialized models for different purposes:

```python
class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=100)

class UserUpdate(SQLModel):
    email: str | None = Field(default=None, max_length=255)
    full_name: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, min_length=8, max_length=100)
    is_active: bool | None = None

class UserPublic(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime
    # Note: no hashed_password field - never expose this!
```

**Why separate models instead of reusing the database model?**

- **Security**: `UserPublic` excludes sensitive fields like `hashed_password`, preventing accidental exposure of credentials in API responses
- **Validation**: `UserCreate` requires a password but `UserUpdate` makes it optional, matching real-world usage patterns where users don't always change their password
- **API clarity**: Frontend developers know exactly what fields they can send and what they'll receive back, reducing integration bugs and support requests
- **Evolution**: You can change database fields without breaking API contracts, and vice versa

## Connecting to the Database: The Async Way

Now let's look at how neodyme handles database connections. Traditional approaches create new connections for every request, which is inefficient and doesn't scale. Neodyme uses connection pooling and async sessions:

```python
# From neodyme's core/database.py (simplified)
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

# Create the engine once when the app starts
engine = create_async_engine(
    settings.database_url,
    **settings.database_engine_options,
)

# Create a session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session
```

**Why this approach works better than simple connections:**

- **Connection pooling**: The engine maintains a pool of database connections that are reused across requests, dramatically reducing connection overhead and preventing "too many connections" errors under load
- **Async operations**: Database queries don't block other requests, allowing your API to handle thousands of concurrent users even with slow database operations
- **Automatic cleanup**: The `async with` pattern ensures connections are returned to the pool even if errors occur, preventing connection leaks that can crash your server
- **Configuration**: Engine options can be tuned for production (connection timeouts, pool sizes, etc.) without changing application code

### Step 3: Creating Tables Automatically

Instead of writing SQL DDL statements manually, neodyme creates tables from your models:

```python
async def create_db_and_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
```

**Why automatic table creation is powerful:**

- **Schema synchronization**: Your database structure automatically matches your model definitions, eliminating the common problem where code and database get out of sync
- **Development speed**: New developers can get a working database with one command instead of running complex migration scripts
- **Type safety**: Column types, constraints, and indexes are generated from your Python type hints, reducing configuration errors

But there's a catch: this approach works great for development, but production requires database migrations (which we'll cover in Chapter 4). The automatic approach ensures your development environment always matches your code.

## The Repository Pattern: Clean Data Access

Raw SQL queries scattered throughout your code create maintenance nightmares. Neodyme uses the repository pattern to centralize database access:

```python
# From neodyme's repositories/base.py (simplified)
from typing import Generic, TypeVar
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

ModelType = TypeVar("ModelType", bound=SQLModel)
CreateSchemaType = TypeVar("CreateSchemaType", bound=SQLModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=SQLModel)

class BaseRepository(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    def __init__(self, model: type[ModelType]) -> None:
        self.model = model

    async def get(self, session: AsyncSession, id: Any) -> ModelType | None:
        statement = select(self.model).where(self.model.id == id)
        result = await session.exec(statement)
        return result.first()

    async def create(self, session: AsyncSession, *, obj_in: CreateSchemaType) -> ModelType:
        obj_data = obj_in.model_dump()
        db_obj = self.model(**obj_data)
        session.add(db_obj)
        await session.commit()
        await session.refresh(db_obj)
        return db_obj
```

**Why the repository pattern solves critical problems:**

- **Code reuse**: Common operations like "get by ID" or "create record" are implemented once and reused everywhere, eliminating duplicate code and reducing bugs
- **Testing**: You can easily mock repositories for unit tests, allowing you to test business logic without hitting an actual database
- **Database independence**: Switching from SQLite to PostgreSQL requires changing only the database URL, not scattered SQL queries throughout your code
- **Transaction management**: Repositories handle database sessions consistently, preventing the common bug where you forget to commit or rollback transactions

### Step 4: Implementing User-Specific Logic

The base repository handles generic operations, but real applications need domain-specific queries:

```python
# From neodyme's repositories/user.py
class UserRepository(BaseRepository[User, UserCreate, UserUpdate]):
    async def get_by_email(self, session: AsyncSession, *, email: str) -> User | None:
        statement = select(User).where(User.email == email)
        result = await session.exec(statement)
        return result.first()

    async def create(self, session: AsyncSession, *, obj_in: UserCreate) -> User:
        obj_data = obj_in.model_dump()
        hashed_password = self._hash_password(obj_data.pop("password"))
        obj_data["hashed_password"] = hashed_password

        db_obj = User(**obj_data)
        session.add(db_obj)
        await session.commit()
        await session.refresh(db_obj)
        return db_obj

    def _hash_password(self, password: str) -> str:
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

user_repository = UserRepository(User)
```

**Why this pattern is essential for real applications:**

- **Security**: Password hashing happens automatically in the repository, preventing developers from accidentally storing plain text passwords
- **Business logic**: Domain-specific operations like "find user by email" are centralized and reusable across different parts of your application
- **Consistency**: All user creation goes through the same code path, ensuring business rules (like password hashing) are always applied
- **Singleton pattern**: `user_repository = UserRepository(User)` creates a single instance that's imported everywhere, ensuring consistent behavior

## Hands-On: Building Your First Database Endpoint

Now let's combine everything into a working API endpoint that actually stores data:

### Step 1: Define Your Models

```python
# models.py
from datetime import datetime
from sqlmodel import Field, SQLModel

class UserBase(SQLModel):
    email: str = Field(unique=True, index=True, max_length=255)
    full_name: str = Field(max_length=255)
    is_active: bool = Field(default=True)

class User(UserBase, table=True):
    __tablename__ = "users"
    
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str = Field(max_length=255)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=100)

class UserPublic(UserBase):
    id: int
    created_at: datetime
```

**Stop and think**: Notice how `UserCreate` requires a password but `UserPublic` doesn't include `hashed_password`. This separation prevents security bugs where sensitive data accidentally gets returned to clients.

### Step 2: Set Up Database Connection

```python
# database.py
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

DATABASE_URL = "sqlite+aiosqlite:///./app.db"

engine = create_async_engine(DATABASE_URL)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

async def create_db_and_tables():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

async def get_session():
    async with async_session_maker() as session:
        yield session
```

**Why SQLite for development**: SQLite requires zero setup, stores data in a single file, and supports the same SQL features you'll use in production with PostgreSQL. This eliminates the "it works on my machine" problem that occurs when development and production use different databases.

### Step 3: Create the API Endpoint

```python
# main.py
from fastapi import FastAPI, Depends
from sqlmodel.ext.asyncio.session import AsyncSession
from models import User, UserCreate, UserPublic
from database import create_db_and_tables, get_session
import hashlib

app = FastAPI()

@app.on_event("startup")
async def startup():
    await create_db_and_tables()

@app.post("/users/", response_model=UserPublic)
async def create_user(
    user_in: UserCreate,
    session: AsyncSession = Depends(get_session)
):
    # Hash the password
    hashed_password = hashlib.sha256(user_in.password.encode()).hexdigest()
    
    # Create user data
    user_data = user_in.model_dump()
    user_data.pop("password")  # Remove plain text password
    user_data["hashed_password"] = hashed_password
    
    # Save to database
    db_user = User(**user_data)
    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)
    
    return UserPublic.model_validate(db_user)
```

**Let's understand what happens here:**

1. **`user_in: UserCreate`** - FastAPI automatically validates the incoming JSON against your UserCreate model, rejecting requests with missing fields, wrong types, or passwords that are too short
2. **`session: AsyncSession = Depends(get_session)`** - FastAPI automatically provides a database session for this request and ensures it's cleaned up afterward, even if errors occur
3. **Password hashing** - The plain text password is immediately hashed and the original is discarded, ensuring passwords are never stored in plain text
4. **`session.commit()`** - Changes are saved to the database atomically—either the entire user creation succeeds or nothing is saved
5. **`UserPublic.model_validate(db_user)`** - The database object is converted to the public API format, automatically excluding sensitive fields

### Step 4: Test Your Database API

Start your server and visit `http://localhost:8000/docs`. You'll see your endpoint with automatic documentation showing exactly what fields are required and what the response looks like.

Try creating a user:

```json
{
  "email": "test@example.com",
  "full_name": "Test User",
  "password": "securepassword123"
}
```

The response will show:

```json
{
  "email": "test@example.com",
  "full_name": "Test User",
  "is_active": true,
  "id": 1,
  "created_at": "2024-01-01T12:00:00"
}
```

**Notice what's missing**: The password and hashed_password fields are not in the response, demonstrating how the model separation protects sensitive data automatically.

## The Power of Type-Driven Development

Here's what you've achieved with this approach:

**Automatic Validation**: Try sending invalid data—wrong email format, missing fields, passwords that are too short. FastAPI rejects these requests before they reach your code, providing helpful error messages that guide users to fix their input.

**Documentation in Sync**: Your API documentation automatically shows the correct request and response formats because it's generated from the same models that handle the actual data.

**Database Safety**: The type system prevents common bugs like trying to insert strings into integer columns or forgetting required fields.

**Performance**: Async database operations mean your API can handle multiple user registrations simultaneously without blocking.

But there's more. Let's look at error handling:

```python
from fastapi import HTTPException

@app.post("/users/", response_model=UserPublic)
async def create_user(
    user_in: UserCreate,
    session: AsyncSession = Depends(get_session)
):
    # Check if user already exists
    existing_user = await session.exec(
        select(User).where(User.email == user_in.email)
    )
    if existing_user.first():
        raise HTTPException(
            status_code=400, 
            detail="Email already registered"
        )
    
    # ... rest of creation logic
```

**Why explicit error handling matters**: Without this check, the database would reject the duplicate email (because of the unique constraint), but users would get a generic 500 error instead of a helpful message explaining what went wrong.

## Architecture Overview: How the Pieces Fit Together

Here's how data flows through neodyme's architecture:

```
API Request (JSON)
        │
        ▼
   FastAPI Endpoint
        │
        ▼
  UserCreate Model ────► Validation
        │
        ▼
  Repository Layer ────► Business Logic
        │
        ▼
   Database Session ───► SQLModel/SQLAlchemy
        │
        ▼
   Database (SQLite/PostgreSQL)
        │
        ▼
   User Model (Database)
        │
        ▼
  UserPublic Model ────► Serialization  
        │
        ▼
  API Response (JSON)
```

**Each layer has a specific responsibility:**

- **API Layer**: Handles HTTP concerns, request routing, and response formatting
- **Validation Layer**: Ensures data integrity before it reaches business logic
- **Repository Layer**: Encapsulates database operations and domain-specific queries
- **Database Layer**: Handles persistence, transactions, and data storage
- **Serialization Layer**: Converts between internal models and external API formats

This separation means you can change any layer without affecting the others. Need to switch from SQLite to PostgreSQL? Change the database URL. Need to add new validation rules? Modify the models. Need to add caching? Wrap the repository layer.

## What You've Learned

By the end of this chapter, you understand:

✅ **Why in-memory storage fails in production** - and the specific problems that occur when data isn't persistent  
✅ **How SQLModel bridges Python and databases** - using type hints for validation, documentation, and schema generation  
✅ **The model separation pattern** - and why UserCreate, User, and UserPublic solve different problems  
✅ **Async database operations** - and how they enable high-concurrency applications  
✅ **The repository pattern** - and why centralizing database access improves maintainability  
✅ **Connection pooling and session management** - and how proper resource management prevents production failures  

More importantly, you've built your first API that actually stores data safely and efficiently.

## Building Blocks for Next Chapters

This database foundation gives us:
- **HTTP handling** ← Chapter 1: FastAPI basics
- **Data persistence** ← You are here
- **User management** ← Chapter 3: Building complete user workflows
- **Data validation** ← Chapter 3: Request/response validation
- **Error handling** ← Chapter 6: Professional error management

## Exercises

1. **Add a get endpoint**: Create `GET /users/{user_id}` that returns a single user
2. **Add validation**: What happens if you try to create a user with an invalid email?
3. **Test uniqueness**: Try creating two users with the same email address
4. **Explore the database**: Look at the SQLite file that was created—how is your data stored?
5. **Add fields**: Add a `phone_number` field to your User model and see how it affects the API docs

## Resources for Deeper Learning

### SQLModel and Database Patterns
- **SQLModel Official Documentation**: Comprehensive guide to SQLModel features and patterns - https://sqlmodel.tiangolo.com/
- **SQLAlchemy 2.0 Tutorial**: Deep dive into the underlying database toolkit - https://docs.sqlalchemy.org/en/20/tutorial/
- **Async SQLAlchemy**: Guide to asynchronous database operations - https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html

### Repository Pattern and Clean Architecture
- **Repository Pattern Explained**: Why and how to implement data access layers - https://deviq.com/design-patterns/repository-pattern
- **Clean Architecture in Python**: Structuring applications for maintainability - https://github.com/cosmic-python/book

### Database Design and Performance
- **Database Indexing Explained**: Why indexes matter for query performance - https://use-the-index-luke.com/
- **PostgreSQL vs SQLite**: When to use which database - https://www.sqlite.org/whentouse.html

### Security and Best Practices
- **Password Hashing Best Practices**: Why bcrypt is better than SHA256 - https://auth0.com/blog/hashing-passwords-one-way-road-to-security/
- **SQL Injection Prevention**: How ORMs protect against common attacks - https://owasp.org/www-community/attacks/SQL_Injection

### Why These Resources Matter
- **SQLModel specifics**: Understanding the framework's design decisions helps you use it effectively
- **Repository pattern**: Essential for building maintainable applications that can evolve over time
- **Database performance**: Knowing how indexes work prevents performance disasters in production
- **Security practices**: Understanding why certain patterns exist helps you avoid common vulnerabilities

**Pro Tip**: Start with the SQLModel documentation to understand the framework's philosophy, then explore the advanced topics as your application grows in complexity.

## Next: Building Complete User Workflows

You can store users in a database, but a real application needs complete workflows: registration, login, profile updates, password changes, and account management. In Chapter 3, we'll build these features using the foundation you've established.

```python
# Preview of Chapter 3
@app.post("/auth/register/")
async def register_user(user: UserCreate) -> UserPublic:
    # Complete registration workflow with validation
    pass

@app.post("/auth/login/")
async def login(credentials: UserCredentials) -> TokenResponse:
    # Secure authentication with JWT tokens
    pass

@app.put("/users/me/")
async def update_profile(
    updates: UserUpdate,
    current_user: User = Depends(get_current_user)
) -> UserPublic:
    # Profile updates with authorization
    pass
```

We'll explore how the database patterns you learned scale to handle complex user interactions, and why proper validation becomes even more critical as your API grows.
