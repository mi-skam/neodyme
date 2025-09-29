# Chapter 3: "I Need to Validate Data Without Going Crazy"

You can store users in a database now, but there's a problem lurking beneath the surface. Users are creative, malicious, or simply make mistakes. They'll send you emails like "not-an-email", names that are 10,000 characters long, passwords that are empty strings, or JSON that's completely malformed.

Without proper validation, these inputs will crash your server, corrupt your data, or worse—give attackers a way to exploit your system. The question isn't whether bad data will come in; it's how gracefully your API handles it when it does.

## The Problem: Users Send Terrible Data

Let me ask you: Have you ever built a form and assumed users would fill it out correctly? If so, you've learned the hard way that this assumption is always wrong.

Here's what happens in the real world:

```python
# What you hope users send:
{
    "email": "user@example.com",
    "full_name": "John Doe", 
    "password": "securePassword123"
}

# What users actually send:
{
    "email": "definitely-not-an-email",
    "full_name": "A" * 50000,  # 50,000 character name
    "password": "",            # Empty password
    "extra_field": "hack attempt"
}
```

Without validation, this malformed data will:

- **Crash your database** - A 50,000 character string inserted into a VARCHAR(255) field generates database errors that bring down your entire API
- **Break your business logic** - Empty passwords get hashed and stored, creating accounts that nobody can log into
- **Consume excessive memory** - Massive strings eat up RAM and can trigger out-of-memory crashes
- **Enable security attacks** - Extra fields might be processed by vulnerable code paths you didn't expect
- **Create inconsistent data** - Some records have valid emails, others have garbage, making queries and user communication impossible

The real question isn't "How do I validate input?" It's "How do I validate input without writing thousands of lines of repetitive checking code that I'll inevitably get wrong?"

## Why Manual Validation is a Nightmare

Traditional input validation looks like this:

```python
# Manual validation - tedious and error-prone
def create_user(data):
    errors = []
    
    # Email validation
    if not data.get("email"):
        errors.append("Email is required")
    elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', data["email"]):
        errors.append("Invalid email format")
    elif len(data["email"]) > 255:
        errors.append("Email too long")
    
    # Name validation  
    if not data.get("full_name"):
        errors.append("Full name is required")
    elif len(data["full_name"]) > 255:
        errors.append("Name too long")
    elif len(data["full_name"]) < 2:
        errors.append("Name too short")
    
    # Password validation
    if not data.get("password"):
        errors.append("Password is required")
    elif len(data["password"]) < 8:
        errors.append("Password too short")
    elif len(data["password"]) > 100:
        errors.append("Password too long")
    
    # Handle extra fields
    allowed_fields = {"email", "full_name", "password"}
    for key in data.keys():
        if key not in allowed_fields:
            errors.append(f"Unknown field: {key}")
    
    if errors:
        raise ValidationError(errors)
    
    return data
```

**What's wrong with this approach?**

- **Massive code duplication** - Every endpoint needs similar validation logic, leading to thousands of lines of repetitive code
- **Inconsistent rules** - Email validation in the registration endpoint might be different from the profile update endpoint, creating user confusion
- **Hard to maintain** - Change the password length requirement and you need to update validation code in multiple places
- **Easy to forget** - New endpoints often skip validation because developers forget or are in a hurry
- **Poor error messages** - Manual error handling rarely provides the detailed, user-friendly messages that modern applications require
- **No type safety** - Typos in field names (`data["emial"]`) cause runtime errors in production
- **No automatic documentation** - API documentation has to be written separately and often gets out of sync

This approach scales poorly and becomes unmaintainable as your API grows.

## The Pydantic Solution: Type-Driven Validation

What if validation could happen automatically based on type hints you already write? Pydantic (which powers FastAPI) makes this possible:

```python
# Automatic validation with Pydantic models
from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    email: EmailStr = Field(..., max_length=255)
    full_name: str = Field(..., min_length=2, max_length=255)
    password: str = Field(..., min_length=8, max_length=100)
```

This single model definition automatically:

- **Validates email format** - Rejects malformed emails before they reach your business logic
- **Enforces length limits** - Prevents database overflow errors and excessive memory usage
- **Requires all fields** - Catches missing data with helpful error messages
- **Rejects extra fields** - Blocks potential attack vectors from unexpected input
- **Generates documentation** - API docs show exactly what's required and what's optional
- **Provides type safety** - IDEs catch typos and type mismatches during development

But the real power comes from integration with FastAPI, which applies this validation automatically to every request.

## Building Complete User Workflows with Validation

Let's see how neodyme implements complete user management with bulletproof validation. We'll build the full CRUD (Create, Read, Update, Delete) workflow that real applications need.

### Step 1: Comprehensive User Models

First, let's understand why neodyme defines multiple user models:

```python
# From neodyme's models/user.py - comprehensive model set
from datetime import datetime
from sqlmodel import Field, SQLModel

class UserBase(SQLModel):
    """Shared fields that appear in multiple contexts."""
    email: str = Field(unique=True, index=True, max_length=255)
    full_name: str = Field(max_length=255)
    is_active: bool = Field(default=True)

class User(UserBase, table=True):
    """Database model with all fields including sensitive ones."""
    __tablename__ = "users"
    
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str = Field(max_length=255)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False,
        sa_column_kwargs={"onupdate": datetime.utcnow},
    )

class UserCreate(UserBase):
    """Input model for user registration."""
    password: str = Field(min_length=8, max_length=100)

class UserUpdate(SQLModel):
    """Input model for profile updates - all fields optional."""
    email: str | None = Field(default=None, max_length=255)
    full_name: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, min_length=8, max_length=100)
    is_active: bool | None = None

class UserPublic(UserBase):
    """Output model that excludes sensitive information."""
    id: int
    created_at: datetime
    updated_at: datetime
    # Note: no hashed_password field!
```

**Why this model structure solves critical problems:**

- **UserCreate requires all fields** - Registration must provide complete information, preventing accounts with missing data that break the application
- **UserUpdate makes fields optional** - Users can update just their name without providing their password again, matching real-world usage patterns
- **UserPublic excludes passwords** - API responses never contain sensitive data, even if the database query accidentally includes it
- **Shared UserBase** - Common fields are defined once, preventing bugs where registration and updates have different validation rules

### Step 2: User Registration with Complete Validation

Here's how neodyme implements user creation with comprehensive error handling:

```python
# From neodyme's routes/users.py - production-ready user creation
from fastapi import APIRouter, Depends, status
from sqlmodel.ext.asyncio.session import AsyncSession

from neodyme.core import get_async_session
from neodyme.core.exceptions import ConflictError
from neodyme.models import UserCreate, UserPublic
from neodyme.repositories import user_repository

router = APIRouter(prefix="/users", tags=["users"])

@router.post("/", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    session: AsyncSession = Depends(get_async_session),
) -> UserPublic:
    # Check for duplicate email before attempting creation
    existing_user = await user_repository.get_by_email(session, email=user_in.email)
    if existing_user:
        raise ConflictError("Email already registered")

    # Create user (password hashing happens in repository)
    user = await user_repository.create(session, obj_in=user_in)
    return UserPublic.model_validate(user)
```

**Let's trace what happens when someone tries to register:**

1. **FastAPI validates the request** - Before your code runs, FastAPI checks that the JSON matches UserCreate requirements:
   - Email is present and properly formatted
   - Full name is present and within length limits  
   - Password meets length requirements
   - No extra fields are present

2. **Business logic validation** - Your code checks application-specific rules:
   - Email uniqueness (preventing duplicate accounts)
   - Any custom business rules specific to your application

3. **Database constraints** - Even if application validation fails, database constraints provide a final safety net:
   - Unique indexes prevent duplicate emails at the database level
   - Column length limits prevent data truncation

4. **Error handling** - Different types of errors get appropriate HTTP status codes:
   - 400 for malformed requests (handled by FastAPI automatically)
   - 409 for business rule violations (duplicate email)
   - 500 for unexpected system errors

This layered approach means validation failures are caught early and users get helpful error messages instead of cryptic database errors.

### Step 3: User Retrieval with Not Found Handling

Reading users requires different validation patterns:

```python
@router.get("/{user_id}", response_model=UserPublic)
async def get_user(
    user_id: int,
    session: AsyncSession = Depends(get_async_session),
) -> UserPublic:
    user = await user_repository.get(session, id=user_id)
    if not user:
        raise NotFoundError("User not found")

    return UserPublic.model_validate(user)
```

**Why this simple-looking endpoint is more robust than it appears:**

- **Path parameter validation** - FastAPI automatically validates that `user_id` is an integer, rejecting requests like `/users/abc` with helpful error messages
- **Database safety** - The repository pattern prevents SQL injection even if someone bypasses FastAPI validation
- **Consistent error format** - NotFoundError generates a standard 404 response that client applications can handle reliably
- **Data sanitization** - UserPublic.model_validate ensures sensitive fields are never accidentally included in responses

### Step 4: User Updates with Partial Validation

User profile updates are more complex because they need to handle partial data:

```python
@router.put("/{user_id}", response_model=UserPublic)
async def update_user(
    user_id: int,
    user_in: UserUpdate,
    session: AsyncSession = Depends(get_async_session),
) -> UserPublic:
    # First, verify the user exists
    user = await user_repository.get(session, id=user_id)
    if not user:
        raise NotFoundError("User not found")

    # Check email uniqueness only if email is being changed
    if user_in.email:
        existing_user = await user_repository.get_by_email(session, email=user_in.email)
        if existing_user and existing_user.id != user_id:
            raise ConflictError("Email already registered")

    # Extract only the fields that were actually provided
    update_data = user_in.model_dump(exclude_unset=True)
    
    # Handle password hashing if password is being changed
    if "password" in update_data:
        update_data["hashed_password"] = user_repository._hash_password(
            update_data.pop("password")
        )

    # Apply updates
    updated_user = await user_repository.update(
        session, db_obj=user, obj_in=update_data
    )
    return UserPublic.model_validate(updated_user)
```

**This endpoint demonstrates several advanced validation patterns:**

- **Existence validation** - Ensures you can't update users that don't exist, preventing silent failures
- **Conditional uniqueness checking** - Only validates email uniqueness if the email is actually being changed, avoiding unnecessary database queries
- **Exclude unset pattern** - `model_dump(exclude_unset=True)` only includes fields that were explicitly provided in the request, allowing partial updates without overwriting existing data with None values
- **Security transformation** - Plain text passwords are automatically hashed and the original is discarded, ensuring passwords are never stored in plain text even if the hashing logic is accidentally bypassed elsewhere

### Step 5: User Deletion with Safety Checks

Even deletion needs validation:

```python
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    session: AsyncSession = Depends(get_async_session),
) -> None:
    user = await user_repository.get(session, id=user_id)
    if not user:
        raise NotFoundError("User not found")

    await user_repository.delete(session, id=user_id)
```

**Why deletion validation matters:**

- **Idempotent behavior** - Attempting to delete a non-existent user returns a clear error instead of silently succeeding, making client applications more reliable
- **Audit trail** - The existence check creates a log entry showing that a valid user was deleted, not just that a delete operation was attempted
- **Cascade safety** - Future versions can add checks for related data (user's posts, orders, etc.) before allowing deletion

## Error Handling: Making Failures Helpful

Bad data is inevitable, so good error handling is essential. Neodyme implements a comprehensive error handling system:

```python
# From neodyme's core/exceptions.py - structured error handling
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

class NeodymeException(Exception):
    """Base exception for application-specific errors."""
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)

class NotFoundError(NeodymeException):
    """Raised when a requested resource doesn't exist."""
    pass

class ConflictError(NeodymeException):
    """Raised when a request conflicts with existing data."""
    pass

async def neodyme_exception_handler(
    request: Request, exc: NeodymeException
) -> JSONResponse:
    """Convert application exceptions to appropriate HTTP responses."""
    if isinstance(exc, NotFoundError):
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, ConflictError):
        status_code = status.HTTP_409_CONFLICT
    else:
        status_code = status.HTTP_400_BAD_REQUEST

    return JSONResponse(
        status_code=status_code,
        content={"detail": exc.message},
    )
```

**Why structured error handling is crucial for user experience:**

- **Consistent error format** - All errors follow the same JSON structure, making client applications easier to write and debug
- **Appropriate HTTP status codes** - Different error types get correct status codes (404 for not found, 409 for conflicts), allowing client applications to handle errors appropriately
- **User-friendly messages** - Error messages are written for end users, not developers, improving the overall application experience
- **Security considerations** - Error messages don't expose sensitive information like database schema details or internal file paths

### Validation Error Examples

Let's see what happens when users send bad data:

```python
# Request with validation errors:
POST /users/
{
    "email": "not-an-email",
    "full_name": "",
    "password": "123"
}

# Automatic FastAPI response:
HTTP 422 Unprocessable Entity
{
    "detail": [
        {
            "type": "value_error",
            "loc": ["body", "email"],
            "msg": "value is not a valid email address",
            "input": "not-an-email"
        },
        {
            "type": "string_too_short",
            "loc": ["body", "full_name"],
            "msg": "String should have at least 1 character",
            "input": ""
        },
        {
            "type": "string_too_short",
            "loc": ["body", "password"],
            "msg": "String should have at least 8 characters",
            "input": "123"
        }
    ]
}
```

**This detailed error response helps users fix their input:**

- **Field-specific errors** - Each field gets its own error message, so users know exactly what to fix
- **Clear error types** - Error types like "string_too_short" are self-explanatory and can be handled programmatically by client applications
- **Input echoing** - The actual input value is included (safely) so users can see what was problematic
- **Location information** - The `loc` field shows exactly where in the request the error occurred

## Hands-On: Building a Complete User API

Let's combine everything into a working user management system:

### Step 1: Set Up Your Models with Comprehensive Validation

```python
# models.py
from datetime import datetime
from typing import Optional
from pydantic import EmailStr, Field
from sqlmodel import SQLModel

class UserBase(SQLModel):
    email: EmailStr = Field(max_length=255, description="User's email address")
    full_name: str = Field(min_length=2, max_length=255, description="User's full name")
    is_active: bool = Field(default=True, description="Whether the user account is active")

class User(UserBase, table=True):
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str = Field(max_length=255)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(UserBase):
    password: str = Field(
        min_length=8, 
        max_length=100, 
        description="Password must be 8-100 characters"
    )

class UserUpdate(SQLModel):
    email: Optional[EmailStr] = Field(default=None, max_length=255)
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=255)
    password: Optional[str] = Field(default=None, min_length=8, max_length=100)
    is_active: Optional[bool] = None

class UserPublic(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime
```

**Notice the validation details:**

- **EmailStr type** - Automatically validates email format and provides better error messages than regex patterns
- **Field descriptions** - These appear in the automatic API documentation, helping frontend developers understand requirements
- **Consistent length limits** - Same validation rules across create and update operations prevent confusion

### Step 2: Implement the Complete CRUD API

```python
# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from typing import List

app = FastAPI(title="User Management API", version="1.0.0")

# Custom exceptions
class NotFoundError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=404, detail=detail)

class ConflictError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=409, detail=detail)

# CRUD endpoints
@app.post("/users/", response_model=UserPublic, status_code=201)
async def create_user(
    user_in: UserCreate,
    session: AsyncSession = Depends(get_session)
):
    """Create a new user account."""
    # Check for existing email
    existing = await get_user_by_email(session, user_in.email)
    if existing:
        raise ConflictError("Email already registered")
    
    # Create user
    user = await create_user_in_db(session, user_in)
    return user

@app.get("/users/{user_id}", response_model=UserPublic)
async def get_user(
    user_id: int,
    session: AsyncSession = Depends(get_session)
):
    """Get a user by ID."""
    user = await get_user_by_id(session, user_id)
    if not user:
        raise NotFoundError("User not found")
    return user

@app.get("/users/", response_model=List[UserPublic])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    session: AsyncSession = Depends(get_session)
):
    """List users with pagination."""
    users = await get_users(session, skip=skip, limit=limit)
    return users

@app.put("/users/{user_id}", response_model=UserPublic)
async def update_user(
    user_id: int,
    user_in: UserUpdate,
    session: AsyncSession = Depends(get_session)
):
    """Update a user's profile."""
    user = await get_user_by_id(session, user_id)
    if not user:
        raise NotFoundError("User not found")
    
    # Check email uniqueness if email is being changed
    if user_in.email and user_in.email != user.email:
        existing = await get_user_by_email(session, user_in.email)
        if existing:
            raise ConflictError("Email already registered")
    
    updated_user = await update_user_in_db(session, user, user_in)
    return updated_user

@app.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    session: AsyncSession = Depends(get_session)
):
    """Delete a user account."""
    user = await get_user_by_id(session, user_id)
    if not user:
        raise NotFoundError("User not found")
    
    await delete_user_from_db(session, user_id)
```

### Step 3: Test Your Validation

Visit `http://localhost:8000/docs` and try these test cases:

**Valid user creation:**
```json
{
  "email": "user@example.com",
  "full_name": "John Doe",
  "password": "securePassword123"
}
```

**Invalid email:**
```json
{
  "email": "not-an-email",
  "full_name": "John Doe", 
  "password": "securePassword123"
}
```

**Password too short:**
```json
{
  "email": "user@example.com",
  "full_name": "John Doe",
  "password": "123"
}
```

**Extra fields (rejected automatically):**
```json
{
  "email": "user@example.com",
  "full_name": "John Doe",
  "password": "securePassword123",
  "hacker_field": "malicious_content"
}
```

**Observe how FastAPI provides detailed, helpful error messages for each validation failure.**

## The Validation Architecture

Here's how validation flows through neodyme's architecture:

```
    HTTP Request
         │
         ▼
   FastAPI Router
         │
         ▼
   Pydantic Model ────► Field Validation
         │                 ├─ Type checking
         ▼                 ├─ Length limits  
   Route Handler           ├─ Format validation
         │                 └─ Required fields
         ▼
   Business Logic ────► Application Rules
         │                 ├─ Uniqueness checks
         ▼                 ├─ Authorization
   Repository Layer        └─ Business constraints
         │
         ▼
   Database Layer ────► Final Safety Net
         │                 ├─ Column constraints
         ▼                 ├─ Foreign keys
   Persistent Storage      └─ Database rules
```

**Each layer catches different types of problems:**

- **Pydantic Layer**: Format, type, and basic constraint validation
- **Business Layer**: Application-specific rules like uniqueness and authorization
- **Database Layer**: Final enforcement of data integrity constraints

This defensive approach means bugs in one layer don't cause system-wide failures.

## What You've Learned

By the end of this chapter, you understand:

✅ **Why manual validation is unmaintainable** - and leads to security vulnerabilities and inconsistent user experiences  
✅ **How Pydantic automates validation** - using type hints to generate comprehensive input checking  
✅ **The model separation strategy** - and why Create, Update, and Public models solve different validation needs  
✅ **Layered validation architecture** - and how multiple validation layers provide defense in depth  
✅ **Complete CRUD workflows** - with proper error handling and user-friendly error messages  
✅ **Error handling patterns** - that provide helpful feedback while maintaining security  

More importantly, you've built a complete user management system that handles bad input gracefully and provides excellent developer and user experiences.

## Building Blocks for Next Chapters

This validation foundation gives us:
- **HTTP handling** ← Chapter 1: FastAPI basics
- **Data persistence** ← Chapter 2: Database integration
- **Input validation** ← You are here
- **Complete user workflows** ← You are here
- **Error handling** ← Chapter 6: Professional error management (expanding on what we started)

## Exercises

1. **Test validation edge cases**: What happens with Unicode characters, very long strings, or special email formats?
2. **Add custom validation**: Create a validator that ensures passwords contain at least one uppercase letter
3. **Test error responses**: Send malformed JSON and observe how FastAPI handles it
4. **Implement soft delete**: Modify user deletion to set `is_active = False` instead of removing records
5. **Add pagination**: Implement proper pagination with next/previous links in the user list endpoint

## Resources for Deeper Learning

### Pydantic and Data Validation
- **Pydantic Official Documentation**: Comprehensive guide to validation features - https://docs.pydantic.dev/
- **FastAPI Request Validation**: How FastAPI integrates with Pydantic - https://fastapi.tiangolo.com/tutorial/body/
- **Field Validation**: Advanced validation patterns and custom validators - https://docs.pydantic.dev/usage/validators/

### Error Handling and API Design
- **HTTP Status Codes Guide**: When to use which status codes - https://httpstatuses.com/
- **RESTful API Design**: Best practices for API endpoints and error responses - https://restfulapi.net/
- **Problem Details Specification**: Standard format for API error responses - https://tools.ietf.org/html/rfc7807

### Security and Input Validation
- **OWASP Input Validation**: Security considerations for data validation - https://owasp.org/www-community/vulnerabilities/Input_validation
- **SQL Injection Prevention**: How ORMs protect against attacks - https://owasp.org/www-community/attacks/SQL_Injection
- **Email Validation Best Practices**: Why email validation is more complex than it seems - https://emailregex.com/

### Testing and Quality Assurance
- **Property-Based Testing**: Using Hypothesis to test validation logic - https://hypothesis.readthedocs.io/
- **API Testing with pytest**: Comprehensive testing strategies - https://pytest-with-eric.com/api-testing/
- **Fuzzing for Input Validation**: Finding edge cases in validation logic - https://owasp.org/www-community/Fuzzing

### Why These Resources Matter
- **Pydantic mastery**: Understanding the validation framework deeply helps you write more robust applications
- **Error handling standards**: Following HTTP conventions makes your API easier for others to integrate with
- **Security awareness**: Understanding attack vectors helps you design safer validation rules
- **Testing strategies**: Comprehensive testing prevents validation bugs from reaching production

**Pro Tip**: Focus on the Pydantic documentation first to understand the full range of validation options available, then explore testing strategies to ensure your validation logic works correctly under all conditions.

## Next: Building Clean Architecture That Scales

You have a working user management system with solid validation, but as your API grows, you'll face new challenges: How do you organize code so new features don't break existing ones? How do you handle complex business logic? How do you make your code testable and maintainable?

In Chapter 5, we'll explore the architectural patterns that keep large applications organized and maintainable.

```python
# Preview of Chapter 5
class UserService:
    """Business logic layer that coordinates between repositories and external services."""
    
    async def register_user(self, user_data: UserCreate) -> UserPublic:
        # Complex workflow: validation, creation, welcome email, analytics
        pass
    
    async def authenticate_user(self, credentials: LoginRequest) -> TokenResponse:
        # Multi-step authentication with rate limiting and logging
        pass
```

We'll explore how neodyme's service layer manages complex workflows while keeping individual components simple and testable.
