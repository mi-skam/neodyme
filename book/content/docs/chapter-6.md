---
title: "Chapter 6"
weight: 6
type: docs
---
# Chapter 6: "I Need to Handle Errors Like a Professional"

Your service layer architecture is working beautifully. Complex workflows are organized, dependencies are injected cleanly, and testing is straightforward. But then users start reporting mysterious 500 errors, customer support can't explain what went wrong, and you spend hours debugging issues that should have been caught immediately.

The harsh reality of production systems is that **everything that can go wrong, will go wrong**—and usually at the worst possible moment. The question isn't whether errors will occur; it's whether your error handling will help or hinder you when they do.

## The Problem: Errors That Don't Help Anyone

Let me ask you: Have you ever seen an error message that made you more confused than before you read it? If so, you've experienced the pain of poor error handling.

Here's what typically happens when error handling is an afterthought:

```python
# What users see when things go wrong
HTTP 500 Internal Server Error
{
    "detail": "Internal server error"
}

# What developers see in logs (if they're lucky)
ERROR: Exception occurred
Traceback (most recent call last):
  File "some_file.py", line 42, in create_user
    await email_service.send_welcome_email(user)
  File "email_service.py", line 15, in send_welcome_email
    server.login(username, password)
smtplib.SMTPAuthenticationError: 535 Authentication failed

# What customer support sees
Customer: "I can't register, it says internal server error"
Support: "Let me check... I have no idea what went wrong"
```

**Why this approach creates systematic problems:**

- **User frustration** - Generic error messages provide no guidance on how to fix problems, leading to support tickets and abandoned workflows
- **Support team helplessness** - Customer service can't help users without understanding what actually went wrong
- **Developer investigation nightmares** - Vague error messages require hours of log diving to understand simple issues
- **Security leaks** - Poor error handling either exposes sensitive information or hides it so well that debugging becomes impossible
- **Business impact** - Users abandon processes instead of completing them, directly affecting revenue and conversion rates
- **Operational overhead** - Every error becomes a debugging session instead of a quick fix

The fundamental problem is that **different audiences need different information** from the same error, but most applications only provide one error message for everyone.

## Why Generic Error Messages Fail Everyone

Traditional error handling treats all errors the same way:

```python
# The "handle everything the same" approach
@app.exception_handler(Exception)
async def catch_all_handler(request: Request, exc: Exception):
    logger.error(f"An error occurred: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )
```

**This approach fails because:**

- **Users get no actionable information** - "Internal server error" doesn't help them understand if they should retry, change their input, or contact support
- **Developers lose critical context** - Knowing that "an error occurred" doesn't help identify the root cause or fix the underlying issue
- **Support teams can't triage** - Without error context, every issue requires escalation to developers
- **Monitoring becomes impossible** - All errors look the same, making it impossible to identify patterns or prioritize fixes
- **User experience degrades** - Users assume the application is broken rather than understanding they made a correctable mistake

## The Professional Error Handling Solution

Professional error handling provides the right information to the right audience at the right time. Here's how neodyme implements this:

```python
# core/exceptions.py - Structured error hierarchy
from enum import Enum
from typing import Dict, Any, Optional
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

class ErrorCode(Enum):
    """Standardized error codes for consistent handling."""
    USER_NOT_FOUND = "USER_NOT_FOUND"
    EMAIL_ALREADY_EXISTS = "EMAIL_ALREADY_EXISTS"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    EMAIL_SERVICE_UNAVAILABLE = "EMAIL_SERVICE_UNAVAILABLE"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    VALIDATION_FAILED = "VALIDATION_FAILED"

class NeodymeError(Exception):
    """Base exception with rich error context."""
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode,
        user_message: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        http_status: int = 400
    ):
        self.message = message  # For developers
        self.error_code = error_code  # For programmatic handling
        self.user_message = user_message or message  # For end users
        self.context = context or {}  # For debugging
        self.http_status = http_status
        super().__init__(message)

class UserNotFoundError(NeodymeError):
    """Raised when a requested user doesn't exist."""
    
    def __init__(self, user_id: Any, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"User with ID {user_id} not found",
            error_code=ErrorCode.USER_NOT_FOUND,
            user_message="The requested user account could not be found",
            context={"user_id": user_id, **(context or {})},
            http_status=404
        )

class EmailAlreadyExistsError(NeodymeError):
    """Raised when attempting to register with existing email."""
    
    def __init__(self, email: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Email {email} already registered",
            error_code=ErrorCode.EMAIL_ALREADY_EXISTS,
            user_message="An account with this email address already exists. Try logging in instead.",
            context={"email": email, **(context or {})},
            http_status=409
        )

class EmailServiceError(NeodymeError):
    """Raised when email service is unavailable."""
    
    def __init__(self, operation: str, underlying_error: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Email service failed during {operation}: {underlying_error}",
            error_code=ErrorCode.EMAIL_SERVICE_UNAVAILABLE,
            user_message="We're having trouble sending emails right now. Your account was created successfully, but you may not receive confirmation emails.",
            context={"operation": operation, "underlying_error": underlying_error, **(context or {})},
            http_status=503
        )
```

**Why this structured approach solves the error handling problems:**

- **Multiple audiences served** - Each error provides both technical details for developers and user-friendly messages for end users
- **Programmatic error handling** - Error codes allow client applications to handle specific error types appropriately
- **Rich debugging context** - Context dictionaries provide all relevant information for investigation without exposing sensitive data
- **Appropriate HTTP status codes** - Different error types get correct status codes, enabling proper client behavior
- **Consistent error structure** - All errors follow the same pattern, making them predictable and easy to handle

## Implementing Error Context and Logging

Professional error handling requires rich context for debugging. Here's how neodyme captures and logs error information:

```python
# core/error_handler.py - Centralized error processing
import logging
import traceback
from typing import Any, Dict
from datetime import datetime
from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

class ErrorHandler:
    """Centralized error handling with context and logging."""
    
    def __init__(self):
        self.error_metrics = {}  # In production, use proper metrics service
    
    async def handle_neodyme_error(
        self, 
        request: Request, 
        error: NeodymeError
    ) -> JSONResponse:
        """Handle application-specific errors with full context."""
        
        # Build request context for debugging
        request_context = await self._build_request_context(request)
        
        # Combine error context with request context
        full_context = {
            **error.context,
            **request_context,
            "error_code": error.error_code.value,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Log with appropriate level based on error type
        if error.http_status >= 500:
            logger.error(
                f"Server error: {error.message}",
                extra={"context": full_context},
                exc_info=True
            )
        elif error.http_status >= 400:
            logger.warning(
                f"Client error: {error.message}",
                extra={"context": full_context}
            )
        
        # Track error metrics
        self._track_error_metrics(error, full_context)
        
        # Return appropriate response for users
        return JSONResponse(
            status_code=error.http_status,
            content={
                "error": {
                    "code": error.error_code.value,
                    "message": error.user_message,
                    "request_id": request_context.get("request_id")
                }
            }
        )
    
    async def handle_unexpected_error(
        self,
        request: Request,
        error: Exception
    ) -> JSONResponse:
        """Handle unexpected errors with security and debugging balance."""
        
        request_context = await self._build_request_context(request)
        
        # Log full technical details for developers
        logger.error(
            f"Unexpected error: {type(error).__name__}: {str(error)}",
            extra={"context": request_context},
            exc_info=True
        )
        
        # Track critical error metrics
        self._track_critical_error(error, request_context)
        
        # Return generic message to users (security)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred. Please try again later.",
                    "request_id": request_context.get("request_id")
                }
            }
        )
    
    async def _build_request_context(self, request: Request) -> Dict[str, Any]:
        """Build comprehensive request context for debugging."""
        return {
            "request_id": getattr(request.state, "request_id", "unknown"),
            "method": request.method,
            "url": str(request.url),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown"),
            "endpoint": request.url.path,
            "query_params": dict(request.query_params),
            # Don't log sensitive headers like Authorization
            "headers": {
                k: v for k, v in request.headers.items() 
                if k.lower() not in {"authorization", "cookie", "x-api-key"}
            }
        }
    
    def _track_error_metrics(self, error: NeodymeError, context: Dict[str, Any]) -> None:
        """Track error metrics for monitoring and alerting."""
        error_key = error.error_code.value
        if error_key not in self.error_metrics:
            self.error_metrics[error_key] = {"count": 0, "last_seen": None}
        
        self.error_metrics[error_key]["count"] += 1
        self.error_metrics[error_key]["last_seen"] = datetime.utcnow()
        
        # In production, send to metrics service like Prometheus or DataDog
        logger.info(f"Error metric tracked: {error_key}")
    
    def _track_critical_error(self, error: Exception, context: Dict[str, Any]) -> None:
        """Track unexpected errors that need immediate attention."""
        # In production, trigger alerts for 5xx errors
        logger.critical(
            f"Critical error requiring investigation: {type(error).__name__}",
            extra={"context": context}
        )

# Set up global error handlers
error_handler = ErrorHandler()

async def neodyme_exception_handler(request: Request, exc: NeodymeError) -> JSONResponse:
    """Global handler for application-specific errors."""
    return await error_handler.handle_neodyme_error(request, exc)

async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global handler for unexpected errors."""
    return await error_handler.handle_unexpected_error(request, exc)
```

**Why comprehensive error context is essential:**

- **Faster debugging** - Request context helps developers reproduce issues quickly without asking users for details
- **User correlation** - Request IDs allow support teams to find the exact error in logs when users report problems
- **Security balance** - Technical details are logged for developers while users see only safe, helpful messages
- **Metrics foundation** - Error tracking enables monitoring trends and identifying systemic issues before they become critical

## Service Layer Error Propagation

Errors from the service layer need careful handling to maintain the separation of concerns:

```python
# services/user_service.py - Service layer error handling
from neodyme.core.exceptions import UserNotFoundError, EmailAlreadyExistsError, EmailServiceError

class UserService:
    """User service with comprehensive error handling."""
    
    async def register_user(
        self, 
        session: AsyncSession, 
        user_data: UserCreate,
        ip_address: str
    ) -> UserPublic:
        """Register user with detailed error handling."""
        
        try:
            # Check for existing user
            existing_user = await self.user_repository.get_by_email(
                session, email=user_data.email
            )
            if existing_user:
                raise EmailAlreadyExistsError(
                    email=user_data.email,
                    context={"attempted_registration_ip": ip_address}
                )
            
            # Create user (core operation that should not fail)
            user = await self.user_repository.create(session, obj_in=user_data)
            
            # Handle side effects with graceful error handling
            await self._handle_registration_side_effects(user, ip_address)
            
            return UserPublic.model_validate(user)
            
        except NeodymeError:
            # Re-raise application errors as-is
            raise
        except Exception as e:
            # Wrap unexpected errors with context
            logger.error(f"Unexpected error during user registration: {e}")
            raise NeodymeError(
                message=f"User registration failed due to unexpected error: {e}",
                error_code=ErrorCode.INTERNAL_ERROR,
                user_message="Registration failed due to a system error. Please try again.",
                context={
                    "email": user_data.email,
                    "ip_address": ip_address,
                    "underlying_error": str(e)
                }
            ) from e
    
    async def _handle_registration_side_effects(self, user: User, ip_address: str) -> None:
        """Handle registration side effects with appropriate error handling."""
        
        # Email sending - warn but don't fail registration
        try:
            await self.email_service.send_welcome_email(user)
        except Exception as e:
            logger.warning(f"Failed to send welcome email to {user.email}: {e}")
            # Continue - email failure shouldn't prevent registration
        
        # Analytics tracking - warn but don't fail registration
        try:
            await self.analytics_service.track_user_registration(user)
        except Exception as e:
            logger.warning(f"Failed to track registration analytics for user {user.id}: {e}")
            # Continue - analytics failure shouldn't prevent registration
        
        # Audit logging - this might be more critical
        try:
            await self.audit_service.log_user_creation(user, ip_address)
        except Exception as e:
            logger.error(f"Failed to log user creation audit for user {user.id}: {e}")
            # Decision point: fail registration if audit logging fails?
            # For compliance reasons, you might want to fail here
    
    async def get_user_by_id(self, session: AsyncSession, user_id: int) -> UserPublic:
        """Get user with proper error handling."""
        
        try:
            user = await self.user_repository.get(session, id=user_id)
            if not user:
                raise UserNotFoundError(
                    user_id=user_id,
                    context={"operation": "get_user_by_id"}
                )
            
            return UserPublic.model_validate(user)
            
        except NeodymeError:
            # Re-raise application errors
            raise
        except Exception as e:
            # Wrap database or other unexpected errors
            logger.error(f"Unexpected error retrieving user {user_id}: {e}")
            raise NeodymeError(
                message=f"Failed to retrieve user {user_id}: {e}",
                error_code=ErrorCode.INTERNAL_ERROR,
                user_message="Unable to retrieve user information. Please try again.",
                context={"user_id": user_id, "underlying_error": str(e)}
            ) from e
```

**Why service layer error handling is crucial:**

- **Business logic errors** - Services understand business rules and can provide meaningful error messages for rule violations
- **Context preservation** - Services have access to business context that repositories don't understand
- **Error classification** - Services can distinguish between expected business errors and unexpected system failures
- **Graceful degradation** - Services can handle partial failures in complex workflows appropriately

## Repository Layer Error Handling

The repository layer needs to handle database-specific errors and translate them to business errors:

```python
# repositories/user_repository.py - Repository error handling
from sqlalchemy.exc import IntegrityError, DatabaseError
from neodyme.core.exceptions import EmailAlreadyExistsError, NeodymeError, ErrorCode

class UserRepository(BaseRepository[User, UserCreate, UserUpdate]):
    """User repository with database error handling."""
    
    async def create(self, session: AsyncSession, *, obj_in: UserCreate) -> User:
        """Create user with database error handling."""
        
        try:
            # Hash password
            obj_data = obj_in.model_dump()
            hashed_password = self._hash_password(obj_data.pop("password"))
            obj_data["hashed_password"] = hashed_password
            
            # Create user
            db_obj = User(**obj_data)
            session.add(db_obj)
            await session.commit()
            await session.refresh(db_obj)
            return db_obj
            
        except IntegrityError as e:
            await session.rollback()
            
            # Handle specific constraint violations
            if "users_email_key" in str(e.orig):
                # Email uniqueness constraint violated
                raise EmailAlreadyExistsError(
                    email=obj_in.email,
                    context={"constraint": "email_unique", "database_error": str(e.orig)}
                )
            else:
                # Other integrity constraint violations
                logger.error(f"Integrity constraint violation creating user: {e}")
                raise NeodymeError(
                    message=f"Database constraint violation: {e}",
                    error_code=ErrorCode.VALIDATION_FAILED,
                    user_message="The provided data violates system constraints. Please check your input.",
                    context={"email": obj_in.email, "constraint_error": str(e)}
                )
                
        except DatabaseError as e:
            await session.rollback()
            logger.error(f"Database error creating user: {e}")
            raise NeodymeError(
                message=f"Database error during user creation: {e}",
                error_code=ErrorCode.DATABASE_ERROR,
                user_message="A database error occurred. Please try again later.",
                context={"email": obj_in.email, "database_error": str(e)}
            )
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Unexpected error creating user: {e}")
            raise NeodymeError(
                message=f"Unexpected error during user creation: {e}",
                error_code=ErrorCode.INTERNAL_ERROR,
                user_message="An unexpected error occurred during registration.",
                context={"email": obj_in.email, "unexpected_error": str(e)}
            ) from e
    
    async def get_by_email(self, session: AsyncSession, *, email: str) -> User | None:
        """Get user by email with error handling."""
        
        try:
            statement = select(User).where(User.email == email)
            result = await session.exec(statement)
            return result.first()
            
        except DatabaseError as e:
            logger.error(f"Database error querying user by email: {e}")
            raise NeodymeError(
                message=f"Database error querying user: {e}",
                error_code=ErrorCode.DATABASE_ERROR,
                user_message="Unable to search for user. Please try again later.",
                context={"email": email, "database_error": str(e)}
            )
            
        except Exception as e:
            logger.error(f"Unexpected error querying user by email: {e}")
            raise NeodymeError(
                message=f"Unexpected error querying user: {e}",
                error_code=ErrorCode.INTERNAL_ERROR,
                user_message="An unexpected error occurred while searching for the user.",
                context={"email": email, "unexpected_error": str(e)}
            ) from e
```

**Why repository error handling is important:**

- **Database abstraction** - Business logic shouldn't need to understand SQLAlchemy exceptions
- **Constraint translation** - Database constraint violations are converted to meaningful business errors
- **Recovery opportunities** - Transaction rollbacks ensure database consistency when errors occur
- **Context preservation** - Database errors include relevant business context for debugging

## Testing Error Handling

Comprehensive error handling requires comprehensive testing:

```python
# tests/test_error_handling.py
import pytest
from unittest.mock import AsyncMock, patch
from sqlalchemy.exc import IntegrityError
from neodyme.core.exceptions import EmailAlreadyExistsError, UserNotFoundError
from neodyme.services.user_service import UserService

@pytest.mark.asyncio
async def test_user_registration_duplicate_email_error():
    """Test that duplicate email registration raises proper error."""
    
    # Setup mocks
    user_repository = AsyncMock()
    email_service = AsyncMock()
    analytics_service = AsyncMock()
    
    # Mock existing user
    existing_user = User(id=1, email="test@example.com", full_name="Existing User")
    user_repository.get_by_email.return_value = existing_user
    
    # Create service
    user_service = UserService(
        user_repository=user_repository,
        email_service=email_service,
        analytics_service=analytics_service
    )
    
    # Test data
    user_data = UserCreate(
        email="test@example.com",
        full_name="New User",
        password="password123"
    )
    session = AsyncMock()
    
    # Test that proper error is raised
    with pytest.raises(EmailAlreadyExistsError) as exc_info:
        await user_service.register_user(session, user_data, "192.168.1.1")
    
    # Verify error details
    error = exc_info.value
    assert error.error_code == ErrorCode.EMAIL_ALREADY_EXISTS
    assert "test@example.com" in error.user_message
    assert error.context["email"] == "test@example.com"
    assert error.http_status == 409

@pytest.mark.asyncio
async def test_email_service_failure_doesnt_fail_registration():
    """Test that email service failures don't prevent user registration."""
    
    # Setup mocks
    user_repository = AsyncMock()
    email_service = AsyncMock()
    analytics_service = AsyncMock()
    
    # Mock no existing user
    user_repository.get_by_email.return_value = None
    
    # Mock successful user creation
    created_user = User(
        id=1, 
        email="test@example.com", 
        full_name="Test User",
        hashed_password="hashed"
    )
    user_repository.create.return_value = created_user
    
    # Mock email service failure
    email_service.send_welcome_email.side_effect = Exception("SMTP Error")
    
    # Create service
    user_service = UserService(
        user_repository=user_repository,
        email_service=email_service,
        analytics_service=analytics_service
    )
    
    # Test data
    user_data = UserCreate(
        email="test@example.com",
        full_name="Test User",
        password="password123"
    )
    session = AsyncMock()
    
    # Registration should succeed despite email failure
    result = await user_service.register_user(session, user_data, "192.168.1.1")
    
    # Verify registration succeeded
    assert result.email == "test@example.com"
    assert result.full_name == "Test User"
    
    # Verify email was attempted
    email_service.send_welcome_email.assert_called_once_with(created_user)

@pytest.mark.asyncio
async def test_database_integrity_error_handling():
    """Test that database integrity errors are properly handled."""
    
    # Setup mocks
    user_repository = AsyncMock()
    
    # Mock integrity error (email constraint violation)
    integrity_error = IntegrityError(
        statement="INSERT INTO users...",
        params={},
        orig=Exception("duplicate key value violates unique constraint \"users_email_key\"")
    )
    user_repository.create.side_effect = integrity_error
    
    # Mock no existing user (race condition scenario)
    user_repository.get_by_email.return_value = None
    
    email_service = AsyncMock()
    analytics_service = AsyncMock()
    
    # Create service
    user_service = UserService(
        user_repository=user_repository,
        email_service=email_service,
        analytics_service=analytics_service
    )
    
    # Test data
    user_data = UserCreate(
        email="test@example.com",
        full_name="Test User",
        password="password123"
    )
    session = AsyncMock()
    
    # Should raise EmailAlreadyExistsError
    with pytest.raises(EmailAlreadyExistsError) as exc_info:
        await user_service.register_user(session, user_data, "192.168.1.1")
    
    # Verify proper error conversion
    error = exc_info.value
    assert error.error_code == ErrorCode.EMAIL_ALREADY_EXISTS
    assert "test@example.com" in error.context["email"]

@pytest.mark.asyncio
async def test_user_not_found_error():
    """Test user not found error handling."""
    
    # Setup mocks
    user_repository = AsyncMock()
    user_repository.get.return_value = None  # User not found
    
    email_service = AsyncMock()
    analytics_service = AsyncMock()
    
    # Create service
    user_service = UserService(
        user_repository=user_repository,
        email_service=email_service,
        analytics_service=analytics_service
    )
    
    session = AsyncMock()
    
    # Test that proper error is raised
    with pytest.raises(UserNotFoundError) as exc_info:
        await user_service.get_user_by_id(session, 999)
    
    # Verify error details
    error = exc_info.value
    assert error.error_code == ErrorCode.USER_NOT_FOUND
    assert error.context["user_id"] == 999
    assert error.http_status == 404
    assert "user account could not be found" in error.user_message
```

**Why comprehensive error testing is essential:**

- **Error path coverage** - Error handling code paths need testing just like happy path scenarios
- **Error message validation** - Tests ensure error messages are helpful and don't expose sensitive information
- **Context verification** - Tests confirm that error context includes all necessary debugging information
- **Recovery testing** - Tests verify that systems recover properly from various failure scenarios

## What You've Learned

By the end of this chapter, you understand:

✅ **Why generic error messages fail everyone** - and how different audiences need different information from the same error  
✅ **Structured error hierarchies** - providing appropriate HTTP status codes, error codes, and context for each audience  
✅ **Error propagation patterns** - how errors should flow from repositories through services to API responses  
✅ **External service error handling** - managing failures in services you don't control without breaking core functionality  
✅ **Error context and logging** - capturing the right information for debugging while maintaining security  
✅ **Testing error scenarios** - ensuring error handling works correctly under various failure conditions  

More importantly, you've built error handling that helps users solve their problems while giving developers the information they need to fix issues quickly.

## Building Blocks for Next Chapters

This error handling foundation gives us:
- **HTTP handling** ← Chapter 1: FastAPI basics
- **Data persistence** ← Chapter 2: Database integration  
- **Input validation** ← Chapter 3: Request/response validation
- **Schema evolution** ← Chapter 4: Database migrations
- **Clean architecture** ← Chapter 5: Service layer organization
- **Error handling** ← You are here
- **Security** ← Chapter 7: Authentication and authorization

## Exercises

1. **Add error metrics** - Implement error tracking that counts different error types over time
2. **Create error alerts** - Build a system that alerts when error rates exceed thresholds  
3. **Test error recovery** - Add retry logic for transient external service failures
4. **Implement circuit breakers** - Prevent cascading failures when external services are down
5. **Add error correlation** - Implement request IDs that track errors across service boundaries

## Resources for Deeper Learning

### Error Handling Patterns
- **Effective Error Handling**: Patterns for robust error management - https://www.joelonsoftware.com/2003/10/13/13/
- **Exception Handling Best Practices**: Language-agnostic error handling principles - https://docs.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions
- **Circuit Breaker Pattern**: Preventing cascading failures - https://martinfowler.com/bliki/CircuitBreaker.html

### Logging and Observability
- **Structured Logging**: Best practices for machine-readable logs - https://www.honeycomb.io/blog/structured-logging-and-your-team/
- **Python Logging Best Practices**: Effective logging in Python applications - https://realpython.com/python-logging/
- **Observability vs Monitoring**: Understanding the difference - https://www.honeycomb.io/blog/observability-vs-monitoring/

### HTTP Status Codes and API Design
- **HTTP Status Code Guide**: When to use which status codes - https://httpstatuses.com/
- **API Error Design**: Designing user-friendly API errors - https://blog.restcase.com/rest-api-error-codes-101/
- **Problem Details Specification**: Standard format for HTTP API errors - https://tools.ietf.org/html/rfc7807

### Production Error Management
- **Error Budgets and SLI/SLO**: Managing reliability in production - https://sre.google/sre-book/embracing-risk/
- **Incident Response**: Handling production errors effectively - https://response.pagerduty.com/
- **Error Tracking Tools**: Sentry, Rollbar, and Bugsnag comparison - https://sentry.io/vs/rollbar/

### Why These Resources Matter
- **Error handling patterns**: Understanding proven patterns helps you design robust error handling systems
- **Observability practices**: Effective logging and monitoring are essential for debugging production issues
- **HTTP standards**: Following web standards makes your API easier for clients to integrate with
- **Production practices**: Learning from SRE practices helps you build more reliable systems

**Pro Tip**: Start with structured logging practices to ensure you capture the right information, then focus on error classification and user-friendly error messages.

## Next: Authentication and Authorization

You have comprehensive error handling that helps both users and developers, but now you need to protect your API. How do you verify user identity? How do you control access to different resources? How do you implement secure authentication without creating security vulnerabilities?

In Chapter 7, we'll explore authentication and authorization patterns that keep your API secure while maintaining usability.

```python
# Preview of Chapter 7
class AuthService:
    """Secure authentication and authorization service."""
    
    async def authenticate_user(
        self, 
        credentials: UserCredentials
    ) -> TokenResponse:
        """Verify user credentials and generate secure tokens."""
        # Verify password
        # Generate JWT tokens
        # Track login attempt
        # Return secure token response
        pass
    
    async def authorize_request(
        self,
        token: str,
        required_permissions: List[str]
    ) -> User:
        """Verify token and check permissions."""
        # Validate JWT token
        # Load user permissions
        # Check authorization
        # Return authenticated user
        pass
```

We'll explore how to implement secure authentication that protects against common attacks while providing a smooth user experience.
