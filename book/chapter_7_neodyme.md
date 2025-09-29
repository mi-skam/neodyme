# Chapter 7: "I Need Security That Actually Protects"

Your neodyme application is running beautifully. Users can register, the service layer coordinates complex workflows, and errors are handled professionally. But then your security audit arrives with a damning report:

*"Passwords are stored in plain text. Sessions never expire. No rate limiting on login attempts. Any user can access any other user's data."*

Suddenly, you realize that your perfectly functional application is a security disaster waiting to happen. One data breach, one credential stuffing attack, one privilege escalation exploit, and your users' data—and your reputation—are gone forever.

This is the moment every developer faces: **functionality without security is a liability, not an asset**. The question isn't whether attackers will try to compromise your system—it's whether your security will stop them when they do.

## The Problem: Security Theater vs Real Protection

Let me ask you: Have you ever implemented authentication that "worked" but wouldn't survive five minutes against a determined attacker? If so, you've experienced the difference between security theater and actual security.

Here's what most developers build first:

```python
# What looks like security but isn't
@router.post("/login")
async def login(credentials: dict):
    user = await get_user_by_email(credentials["email"])
    if user and user.password == credentials["password"]:  # Plain text comparison!
        # "Session" management with no expiration
        session_token = f"user_{user.id}_{random.randint(1000, 9999)}"
        return {"token": session_token}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@router.get("/profile")
async def get_profile(user_id: int, token: str):
    # No token validation - any token works!
    if not token.startswith("user_"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # No authorization check - any user can access any profile!
    user = await get_user_by_id(user_id)
    return user
```

**Why this approach creates catastrophic security vulnerabilities:**

- **Password storage catastrophe** - Plain text passwords mean a single database breach exposes every user's credentials for use across all their accounts
- **Predictable session tokens** - Simple numeric tokens can be guessed or brute-forced by attackers within minutes
- **No session expiration** - Stolen tokens work forever, giving attackers permanent access even after users "log out"
- **Missing authorization** - Any authenticated user can access any other user's data by simply changing URL parameters
- **No rate limiting** - Attackers can attempt thousands of login combinations per second without restriction
- **No audit trail** - Security breaches leave no evidence, making forensic analysis and compliance reporting impossible

The fundamental problem is **mistaking authentication for security**. Authentication proves identity, but real security requires authorization, session management, attack prevention, and comprehensive auditing.

## Why "Simple" Security Fails Against Real Attacks

The naive approach to security looks like this:

```python
# "Simple" security that invites attacks
users = {
    "admin@company.com": "password123",  # Weak password stored in plain text
    "user@company.com": "123456"        # Even weaker password
}

@router.post("/login")
async def simple_login(email: str, password: str):
    if users.get(email) == password:
        return {"message": "Login successful", "user": email}
    return {"message": "Login failed"}

# No protection on sensitive endpoints
@router.get("/admin/users")
async def get_all_users():
    return list(users.keys())  # Anyone can access admin functionality!
```

**This approach fails against common attack vectors:**

- **Credential stuffing attacks** - Attackers use automated tools to test millions of leaked username/password combinations from other breaches against your login endpoint
- **Brute force attacks** - Without rate limiting, attackers can test thousands of password combinations per minute until they find valid credentials
- **Session hijacking** - Predictable or non-expiring session tokens can be stolen through network interception or cross-site scripting attacks
- **Privilege escalation** - Lack of proper authorization allows attackers to access administrative functions after compromising any user account
- **Password database breaches** - Plain text passwords make every user vulnerable across all their online accounts when your database is compromised
- **Timing attacks** - Inconsistent response times can leak information about which usernames exist in your system

## The Professional Security Solution: Defense in Depth

Professional security implements multiple overlapping protection layers. Here's how neodyme creates a comprehensive security system:

```python
# core/security.py - Comprehensive security foundation
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
import bcrypt
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, Depends, Request

from neodyme.core.config import settings
from neodyme.models import User
from neodyme.core.exceptions import SecurityError, ErrorCode

class SecurityConfig:
    """Centralized security configuration."""
    # JWT Configuration
    SECRET_KEY = settings.secret_key
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    
    # Password Requirements
    MIN_PASSWORD_LENGTH = 8
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL_CHARS = True
    
    # Rate Limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15
    
    # Session Security
    SECURE_COOKIES = True
    HTTPONLY_COOKIES = True

class PasswordManager:
    """Secure password handling with industry best practices."""
    
    def __init__(self):
        # Use bcrypt with appropriate cost factor
        self.pwd_context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=12  # Computationally expensive enough to slow brute force
        )
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt with salt."""
        # Bcrypt automatically generates unique salt for each password
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash with timing attack protection."""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password meets security requirements."""
        issues = []
        
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            issues.append(f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters")
        
        if SecurityConfig.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            issues.append("Password must contain at least one uppercase letter")
        
        if SecurityConfig.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            issues.append("Password must contain at least one lowercase letter")
        
        if SecurityConfig.REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            issues.append("Password must contain at least one digit")
        
        if SecurityConfig.REQUIRE_SPECIAL_CHARS and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            issues.append("Password must contain at least one special character")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "strength_score": self._calculate_strength_score(password)
        }
    
    def _calculate_strength_score(self, password: str) -> int:
        """Calculate password strength score (0-100)."""
        score = 0
        
        # Length bonus
        score += min(25, len(password) * 2)
        
        # Character diversity bonus
        if any(c.isupper() for c in password):
            score += 15
        if any(c.islower() for c in password):
            score += 15
        if any(c.isdigit() for c in password):
            score += 15
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 20
        
        # Penalty for common patterns
        if password.lower() in ["password", "123456", "qwerty", "admin"]:
            score -= 50
        
        return max(0, min(100, score))

class JWTManager:
    """JWT token management with security best practices."""
    
    def create_access_token(self, user_id: int, permissions: list[str] = None) -> str:
        """Create JWT access token with limited lifetime."""
        expire = datetime.utcnow() + timedelta(minutes=SecurityConfig.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            "sub": str(user_id),  # Subject (user ID)
            "exp": expire,        # Expiration time
            "iat": datetime.utcnow(),  # Issued at
            "type": "access",     # Token type
            "permissions": permissions or []
        }
        
        return jwt.encode(payload, SecurityConfig.SECRET_KEY, algorithm=SecurityConfig.ALGORITHM)
    
    def create_refresh_token(self, user_id: int) -> str:
        """Create JWT refresh token with longer lifetime."""
        expire = datetime.utcnow() + timedelta(days=SecurityConfig.REFRESH_TOKEN_EXPIRE_DAYS)
        
        payload = {
            "sub": str(user_id),
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        
        return jwt.encode(payload, SecurityConfig.SECRET_KEY, algorithm=SecurityConfig.ALGORITHM)
    
    def verify_token(self, token: str, expected_type: str = "access") -> Dict[str, Any]:
        """Verify JWT token and return payload."""
        try:
            payload = jwt.decode(
                token, 
                SecurityConfig.SECRET_KEY, 
                algorithms=[SecurityConfig.ALGORITHM]
            )
            
            # Verify token type
            if payload.get("type") != expected_type:
                raise SecurityError(
                    message=f"Invalid token type. Expected {expected_type}, got {payload.get('type')}",
                    error_code=ErrorCode.INVALID_TOKEN,
                    user_message="Invalid authentication token"
                )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise SecurityError(
                message="Token has expired",
                error_code=ErrorCode.TOKEN_EXPIRED,
                user_message="Your session has expired. Please log in again."
            )
        except jwt.InvalidTokenError as e:
            raise SecurityError(
                message=f"Invalid token: {e}",
                error_code=ErrorCode.INVALID_TOKEN,
                user_message="Invalid authentication token"
            )

# Initialize security components
password_manager = PasswordManager()
jwt_manager = JWTManager()
```

**Why this comprehensive approach provides real security:**

- **Bcrypt password hashing** - Computationally expensive hashing with automatic salt generation makes password cracking infeasible even with database access
- **JWT token security** - Cryptographically signed tokens with expiration prevent forgery and limit breach impact
- **Password strength validation** - Enforced complexity requirements prevent users from choosing easily guessed passwords
- **Token type verification** - Separate access and refresh tokens limit the impact of token theft
- **Timing attack protection** - Consistent password verification timing prevents attackers from detecting valid usernames
- **Centralized security configuration** - Security policies are enforced consistently across the entire application

## Implementing Rate Limiting and Attack Prevention

Real security requires active defense against attack patterns:

```python
# core/rate_limiting.py - Attack prevention system
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional
from collections import defaultdict, deque
from fastapi import Request, HTTPException

class RateLimiter:
    """Rate limiting to prevent brute force attacks."""
    
    def __init__(self):
        # Store attempt counts by IP address
        self.attempts: Dict[str, deque] = defaultdict(lambda: deque())
        # Store lockout times by IP address
        self.lockouts: Dict[str, datetime] = {}
        # Cleanup task to prevent memory leaks
        self._cleanup_task = None
    
    async def check_rate_limit(self, request: Request, max_attempts: int, window_minutes: int) -> None:
        """Check if request is within rate limits."""
        client_ip = self._get_client_ip(request)
        now = datetime.utcnow()
        
        # Check if IP is currently locked out
        if client_ip in self.lockouts:
            lockout_end = self.lockouts[client_ip]
            if now < lockout_end:
                remaining_seconds = int((lockout_end - now).total_seconds())
                raise HTTPException(
                    status_code=429,
                    detail=f"Too many failed attempts. Try again in {remaining_seconds} seconds.",
                    headers={"Retry-After": str(remaining_seconds)}
                )
            else:
                # Lockout expired, remove it
                del self.lockouts[client_ip]
        
        # Clean old attempts outside the window
        window_start = now - timedelta(minutes=window_minutes)
        attempts = self.attempts[client_ip]
        
        while attempts and attempts[0] < window_start:
            attempts.popleft()
        
        # Check if adding this attempt would exceed the limit
        if len(attempts) >= max_attempts:
            # Lock out the IP
            self.lockouts[client_ip] = now + timedelta(minutes=SecurityConfig.LOGIN_LOCKOUT_MINUTES)
            raise HTTPException(
                status_code=429,
                detail=f"Too many attempts. Locked out for {SecurityConfig.LOGIN_LOCKOUT_MINUTES} minutes.",
                headers={"Retry-After": str(SecurityConfig.LOGIN_LOCKOUT_MINUTES * 60)}
            )
        
        # Record this attempt
        attempts.append(now)
    
    def record_failed_attempt(self, request: Request) -> None:
        """Record a failed login attempt for rate limiting."""
        # Attempt is already recorded in check_rate_limit
        pass
    
    def record_successful_attempt(self, request: Request) -> None:
        """Clear rate limiting on successful login."""
        client_ip = self._get_client_ip(request)
        if client_ip in self.attempts:
            self.attempts[client_ip].clear()
        if client_ip in self.lockouts:
            del self.lockouts[client_ip]
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address with proxy header support."""
        # Check for forwarded IP (common in load-balanced setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP (client IP) if multiple proxies
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to direct client IP
        return request.client.host if request.client else "unknown"
    
    async def cleanup_expired_data(self) -> None:
        """Periodic cleanup of expired rate limiting data."""
        now = datetime.utcnow()
        
        # Clean expired lockouts
        expired_lockouts = [
            ip for ip, lockout_time in self.lockouts.items()
            if now > lockout_time
        ]
        for ip in expired_lockouts:
            del self.lockouts[ip]
        
        # Clean old attempts (older than 1 hour)
        cutoff = now - timedelta(hours=1)
        for ip, attempts in list(self.attempts.items()):
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            # Remove empty deques
            if not attempts:
                del self.attempts[ip]

# Global rate limiter instance
rate_limiter = RateLimiter()

# Rate limiting decorator
def rate_limit(max_attempts: int = 5, window_minutes: int = 15):
    """Decorator to add rate limiting to endpoints."""
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            await rate_limiter.check_rate_limit(request, max_attempts, window_minutes)
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator
```

**Why rate limiting is essential for security:**

- **Brute force prevention** - Limits the number of password attempts per IP address, making password cracking infeasible
- **Resource protection** - Prevents attackers from overwhelming your authentication system with rapid requests
- **Lockout mechanisms** - Temporary bans give legitimate users time to secure their accounts while blocking automated attacks
- **Distributed attack resistance** - IP-based limiting handles attacks from multiple source addresses
- **Memory efficiency** - Automatic cleanup prevents rate limiting data from consuming unlimited memory
- **Proxy-aware IP detection** - Correctly identifies client IPs behind load balancers and CDNs

## Building the Authentication Service

The authentication service coordinates all security components:

```python
# services/auth_service.py - Complete authentication workflow
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from neodyme.core.security import password_manager, jwt_manager, rate_limiter
from neodyme.core.exceptions import SecurityError, ErrorCode
from neodyme.models import User, UserCreate
from neodyme.repositories import UserRepository

class AuthService:
    """Comprehensive authentication and authorization service."""
    
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
        self.failed_attempts: Dict[str, list] = {}  # Track failed attempts by email
    
    async def register_user(
        self, 
        session: AsyncSession, 
        user_data: UserCreate,
        request: Request
    ) -> Dict[str, Any]:
        """Register new user with security validation."""
        
        # Validate password strength
        password_validation = password_manager.validate_password_strength(user_data.password)
        if not password_validation["valid"]:
            raise SecurityError(
                message=f"Password validation failed: {password_validation['issues']}",
                error_code=ErrorCode.WEAK_PASSWORD,
                user_message=f"Password requirements not met: {', '.join(password_validation['issues'])}",
                context={"password_issues": password_validation["issues"]}
            )
        
        # Check for existing user
        existing_user = await self.user_repository.get_by_email(session, email=user_data.email)
        if existing_user:
            raise SecurityError(
                message=f"Registration attempted with existing email: {user_data.email}",
                error_code=ErrorCode.EMAIL_ALREADY_EXISTS,
                user_message="An account with this email already exists",
                context={"email": user_data.email}
            )
        
        # Create user with hashed password
        user_dict = user_data.model_dump()
        user_dict["hashed_password"] = password_manager.hash_password(user_dict.pop("password"))
        
        user = await self.user_repository.create(session, obj_in=user_dict)
        
        # Generate tokens
        access_token = jwt_manager.create_access_token(user.id, permissions=["user"])
        refresh_token = jwt_manager.create_refresh_token(user.id)
        
        return {
            "user": UserPublic.model_validate(user),
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    
    async def authenticate_user(
        self, 
        session: AsyncSession, 
        email: str, 
        password: str,
        request: Request
    ) -> Dict[str, Any]:
        """Authenticate user with comprehensive security checks."""
        
        # Apply rate limiting
        await rate_limiter.check_rate_limit(
            request, 
            max_attempts=SecurityConfig.MAX_LOGIN_ATTEMPTS,
            window_minutes=SecurityConfig.LOGIN_LOCKOUT_MINUTES
        )
        
        try:
            # Get user by email
            user = await self.user_repository.get_by_email(session, email=email)
            if not user:
                # Don't reveal whether email exists (timing attack protection)
                await self._simulate_password_check()
                raise SecurityError(
                    message=f"Login attempt with non-existent email: {email}",
                    error_code=ErrorCode.INVALID_CREDENTIALS,
                    user_message="Invalid email or password",
                    context={"email": email, "reason": "user_not_found"}
                )
            
            # Check if account is active
            if not user.is_active:
                raise SecurityError(
                    message=f"Login attempt with inactive account: {email}",
                    error_code=ErrorCode.ACCOUNT_DISABLED,
                    user_message="Account is disabled. Contact support for assistance.",
                    context={"user_id": user.id, "email": email}
                )
            
            # Verify password
            if not password_manager.verify_password(password, user.hashed_password):
                # Record failed attempt
                rate_limiter.record_failed_attempt(request)
                self._record_failed_login(email)
                
                raise SecurityError(
                    message=f"Failed login attempt for user {email}",
                    error_code=ErrorCode.INVALID_CREDENTIALS,
                    user_message="Invalid email or password",
                    context={"user_id": user.id, "email": email, "reason": "invalid_password"}
                )
            
            # Success - clear rate limiting and failed attempts
            rate_limiter.record_successful_attempt(request)
            self._clear_failed_attempts(email)
            
            # Update last login
            await self.user_repository.update(
                session, 
                db_obj=user, 
                obj_in={"last_login": datetime.utcnow()}
            )
            
            # Generate tokens with user permissions
            user_permissions = await self._get_user_permissions(user)
            access_token = jwt_manager.create_access_token(user.id, permissions=user_permissions)
            refresh_token = jwt_manager.create_refresh_token(user.id)
            
            return {
                "user": UserPublic.model_validate(user),
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer"
            }
            
        except SecurityError:
            # Re-raise security errors as-is
            raise
        except Exception as e:
            # Wrap unexpected errors
            logger.error(f"Unexpected error during authentication: {e}")
            raise SecurityError(
                message=f"Authentication system error: {e}",
                error_code=ErrorCode.INTERNAL_ERROR,
                user_message="Authentication temporarily unavailable. Please try again.",
                context={"email": email, "unexpected_error": str(e)}
            ) from e
    
    async def refresh_token(
        self, 
        session: AsyncSession, 
        refresh_token: str
    ) -> Dict[str, Any]:
        """Generate new access token from refresh token."""
        
        # Verify refresh token
        payload = jwt_manager.verify_token(refresh_token, expected_type="refresh")
        user_id = int(payload["sub"])
        
        # Get user and verify they still exist and are active
        user = await self.user_repository.get(session, id=user_id)
        if not user or not user.is_active:
            raise SecurityError(
                message=f"Token refresh attempted for invalid/inactive user: {user_id}",
                error_code=ErrorCode.INVALID_TOKEN,
                user_message="Invalid refresh token",
                context={"user_id": user_id}
            )
        
        # Generate new access token
        user_permissions = await self._get_user_permissions(user)
        access_token = jwt_manager.create_access_token(user.id, permissions=user_permissions)
        
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
    
    async def _simulate_password_check(self) -> None:
        """Simulate password checking to prevent timing attacks."""
        # Perform a fake password hash verification to maintain consistent timing
        fake_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/h/bu6U.qy"
        password_manager.verify_password("fake_password", fake_hash)
    
    async def _get_user_permissions(self, user: User) -> list[str]:
        """Get user permissions for token generation."""
        # Basic permissions for all users
        permissions = ["user"]
        
        # Add admin permissions if user is admin
        if user.is_admin:
            permissions.extend(["admin", "user_management"])
        
        return permissions
    
    def _record_failed_login(self, email: str) -> None:
        """Record failed login attempt for monitoring."""
        now = datetime.utcnow()
        if email not in self.failed_attempts:
            self.failed_attempts[email] = []
        
        self.failed_attempts[email].append(now)
        
        # Keep only attempts from the last hour
        cutoff = now - timedelta(hours=1)
        self.failed_attempts[email] = [
            attempt for attempt in self.failed_attempts[email]
            if attempt > cutoff
        ]
    
    def _clear_failed_attempts(self, email: str) -> None:
        """Clear failed attempts on successful login."""
        if email in self.failed_attempts:
            del self.failed_attempts[email]
```

**Why comprehensive authentication service is critical:**

- **Coordinated security** - All security components work together to provide defense in depth
- **Attack pattern detection** - Failed attempt tracking helps identify brute force attacks
- **Token lifecycle management** - Proper token generation, verification, and refresh prevents session attacks
- **Account status verification** - Disabled accounts can't be used even with valid credentials
- **Timing attack protection** - Consistent response times prevent username enumeration attacks
- **Permission integration** - User permissions are embedded in tokens for efficient authorization

## Authorization and Permission Management

Authentication verifies identity; authorization controls access:

```python
# core/authorization.py - Permission-based access control
from typing import List, Optional
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from neodyme.core.security import jwt_manager
from neodyme.core.exceptions import SecurityError, ErrorCode
from neodyme.models import User
from neodyme.repositories import UserRepository

security = HTTPBearer()

class Permission:
    """Define application permissions."""
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_DELETE = "user:delete"
    ADMIN_READ = "admin:read"
    ADMIN_WRITE = "admin:write"
    SYSTEM_ADMIN = "system:admin"

class AuthorizationService:
    """Handle authorization and permission checking."""
    
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    async def get_current_user(
        self, 
        session: AsyncSession,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> User:
        """Get current authenticated user from token."""
        
        try:
            # Verify and decode token
            payload = jwt_manager.verify_token(credentials.credentials)
            user_id = int(payload["sub"])
            
            # Get user from database
            user = await self.user_repository.get(session, id=user_id)
            if not user:
                raise SecurityError(
                    message=f"Token references non-existent user: {user_id}",
                    error_code=ErrorCode.INVALID_TOKEN,
                    user_message="Invalid authentication token"
                )
            
            if not user.is_active:
                raise SecurityError(
                    message=f"Token for inactive user: {user_id}",
                    error_code=ErrorCode.ACCOUNT_DISABLED,
                    user_message="Account is disabled"
                )
            
            return user
            
        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError(
                message=f"Token validation error: {e}",
                error_code=ErrorCode.INVALID_TOKEN,
                user_message="Invalid authentication token"
            ) from e
    
    async def require_permissions(
        self,
        required_permissions: List[str],
        session: AsyncSession,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> User:
        """Require specific permissions for access."""
        
        # Get current user
        user = await self.get_current_user(session, credentials)
        
        # Get token permissions
        payload = jwt_manager.verify_token(credentials.credentials)
        token_permissions = payload.get("permissions", [])
        
        # Check if user has required permissions
        missing_permissions = []
        for permission in required_permissions:
            if permission not in token_permissions:
                missing_permissions.append(permission)
        
        if missing_permissions:
            raise SecurityError(
                message=f"User {user.id} missing permissions: {missing_permissions}",
                error_code=ErrorCode.INSUFFICIENT_PERMISSIONS,
                user_message="You don't have permission to access this resource",
                context={
                    "user_id": user.id,
                    "required_permissions": required_permissions,
                    "missing_permissions": missing_permissions
                }
            )
        
        return user
    
    async def require_self_or_admin(
        self,
        target_user_id: int,
        session: AsyncSession,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> User:
        """Require user to be accessing their own data or be an admin."""
        
        current_user = await self.get_current_user(session, credentials)
        
        # Allow if user is accessing their own data
        if current_user.id == target_user_id:
            return current_user
        
        # Allow if user has admin permissions
        payload = jwt_manager.verify_token(credentials.credentials)
        token_permissions = payload.get("permissions", [])
        
        if Permission.ADMIN_READ in token_permissions:
            return current_user
        
        raise SecurityError(
            message=f"User {current_user.id} attempted to access user {target_user_id} data",
            error_code=ErrorCode.INSUFFICIENT_PERMISSIONS,
            user_message="You can only access your own data",
            context={
                "current_user_id": current_user.id,
                "target_user_id": target_user_id
            }
        )

# Create authorization service instance
authorization_service = AuthorizationService(user_repository)

# Convenience dependency functions
async def get_current_user(
    session: AsyncSession = Depends(get_async_session),
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """Dependency to get current authenticated user."""
    return await authorization_service.get_current_user(session, credentials)

def require_permissions(permissions: List[str]):
    """Dependency factory to require specific permissions."""
    async def permission_dependency(
        session: AsyncSession = Depends(get_async_session),
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> User:
        return await authorization_service.require_permissions(permissions, session, credentials)
    
    return permission_dependency

def require_self_or_admin(target_user_id: int):
    """Dependency factory to require self-access or admin permissions."""
    async def self_or_admin_dependency(
        session: AsyncSession = Depends(get_async_session),
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> User:
        return await authorization_service.require_self_or_admin(target_user_id, session, credentials)
    
    return self_or_admin_dependency
```

**Why proper authorization prevents privilege escalation:**

- **Permission-based access control** - Granular permissions allow fine-tuned access control without complex role hierarchies
- **Token-embedded permissions** - Permissions are verified without additional database lookups, improving performance
- **Self-access patterns** - Users can access their own data without admin privileges, following principle of least privilege
- **Admin verification** - Administrative actions require explicit admin permissions, preventing unauthorized access
- **Context logging** - Failed authorization attempts are logged with full context for security monitoring

## Secure API Endpoints

Now let's implement secure endpoints using the authentication and authorization system:

```python
# routes/auth.py - Authentication endpoints
from fastapi import APIRouter, Depends, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

from neodyme.services.auth_service import AuthService
from neodyme.core.authorization import get_current_user, require_permissions, Permission
from neodyme.models import UserCreate, UserPublic

router = APIRouter(prefix="/auth", tags=["authentication"])

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=100)

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user: UserPublic

class RefreshRequest(BaseModel):
    refresh_token: str

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    request: Request,
    session: AsyncSession = Depends(get_async_session),
    auth_service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    """Register new user account with comprehensive validation."""
    
    result = await auth_service.register_user(session, user_data, request)
    return TokenResponse(**result)

@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_async_session),
    auth_service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    """Authenticate user and return access tokens."""
    
    result = await auth_service.authenticate_user(
        session, login_data.email, login_data.password, request
    )
    return TokenResponse(**result)

@router.post("/refresh", response_model=dict)
async def refresh_token(
    refresh_data: RefreshRequest,
    session: AsyncSession = Depends(get_async_session),
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """Generate new access token from refresh token."""
    
    result = await auth_service.refresh_token(session, refresh_data.refresh_token)
    return result

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user)
) -> dict:
    """Logout user (client should discard tokens)."""
    
    # In a stateless JWT system, logout is handled client-side
    # For enhanced security, you could maintain a token blacklist
    return {"message": "Logout successful"}

@router.get("/me", response_model=UserPublic)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
) -> UserPublic:
    """Get current authenticated user's profile."""
    
    return UserPublic.model_validate(current_user)

# routes/users.py - Protected user endpoints
@router.get("/{user_id}", response_model=UserPublic)
async def get_user(
    user_id: int,
    current_user: User = Depends(require_self_or_admin(user_id)),
    session: AsyncSession = Depends(get_async_session)
) -> UserPublic:
    """Get user profile (own profile or admin access)."""
    
    if current_user.id == user_id:
        # User accessing their own profile
        return UserPublic.model_validate(current_user)
    else:
        # Admin accessing another user's profile
        user = await user_repository.get(session, id=user_id)
        if not user:
            raise UserNotFoundError(user_id)
        return UserPublic.model_validate(user)

@router.get("/", response_model=List[UserPublic])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(require_permissions([Permission.ADMIN_READ])),
    session: AsyncSession = Depends(get_async_session)
) -> List[UserPublic]:
    """List all users (admin only)."""
    
    users = await user_repository.get_multi(session, skip=skip, limit=limit)
    return [UserPublic.model_validate(user) for user in users]

@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(require_permissions([Permission.USER_DELETE])),
    session: AsyncSession = Depends(get_async_session)
) -> dict:
    """Delete user account (admin only)."""
    
    user = await user_repository.get(session, id=user_id)
    if not user:
        raise UserNotFoundError(user_id)
    
    # Prevent self-deletion
    if user.id == current_user.id:
        raise SecurityError(
            message=f"User {current_user.id} attempted self-deletion",
            error_code=ErrorCode.INVALID_OPERATION,
            user_message="You cannot delete your own account through this endpoint"
        )
    
    await user_repository.delete(session, id=user_id)
    return {"message": "User deleted successfully"}
```

**Why secure endpoint design prevents unauthorized access:**

- **Defense in depth** - Multiple security layers (authentication, authorization, business logic validation) protect each endpoint
- **Principle of least privilege** - Users can only access data and operations they specifically need
- **Self-access optimization** - Users can access their own data efficiently without additional permission checks
- **Admin separation** - Administrative functions require explicit admin permissions and additional validation
- **Operation validation** - Business rules (like preventing self-deletion) are enforced even for authorized users

## Testing Security Implementation

Security code requires comprehensive testing to ensure it actually works:

```python
# tests/test_security.py
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta
import jwt

from neodyme.core.security import password_manager, jwt_manager
from neodyme.core.exceptions import SecurityError, ErrorCode
from neodyme.services.auth_service import AuthService

class TestPasswordManager:
    """Test password security functions."""
    
    def test_password_hashing(self):
        """Test that passwords are hashed securely."""
        password = "securepassword123"
        hashed = password_manager.hash_password(password)
        
        # Hash should be different from original
        assert hashed != password
        
        # Hash should be bcrypt format
        assert hashed.startswith("$2b$")
        
        # Verification should work
        assert password_manager.verify_password(password, hashed)
        
        # Wrong password should fail
        assert not password_manager.verify_password("wrongpassword", hashed)
    
    def test_password_strength_validation(self):
        """Test password strength requirements."""
        # Weak password
        weak_result = password_manager.validate_password_strength("123")
        assert not weak_result["valid"]
        assert "at least 8 characters" in weak_result["issues"][0]
        
        # Strong password
        strong_result = password_manager.validate_password_strength("StrongP@ss123")
        assert strong_result["valid"]
        assert len(strong_result["issues"]) == 0
        assert strong_result["strength_score"] > 80

class TestJWTManager:
    """Test JWT token management."""
    
    def test_token_creation_and_verification(self):
        """Test JWT token lifecycle."""
        user_id = 123
        permissions = ["user", "admin"]
        
        # Create token
        token = jwt_manager.create_access_token(user_id, permissions)
        assert isinstance(token, str)
        
        # Verify token
        payload = jwt_manager.verify_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["permissions"] == permissions
        assert payload["type"] == "access"
    
    def test_token_expiration(self):
        """Test that expired tokens are rejected."""
        user_id = 123
        
        # Create token with past expiration
        with patch('neodyme.core.security.datetime') as mock_datetime:
            past_time = datetime.utcnow() - timedelta(hours=1)
            mock_datetime.utcnow.return_value = past_time
            token = jwt_manager.create_access_token(user_id)
        
        # Verification should fail
        with pytest.raises(SecurityError) as exc_info:
            jwt_manager.verify_token(token)
        
        assert exc_info.value.error_code == ErrorCode.TOKEN_EXPIRED
    
    def test_invalid_token(self):
        """Test that invalid tokens are rejected."""
        invalid_token = "invalid.token.here"
        
        with pytest.raises(SecurityError) as exc_info:
            jwt_manager.verify_token(invalid_token)
        
        assert exc_info.value.error_code == ErrorCode.INVALID_TOKEN

@pytest.mark.asyncio
class TestAuthService:
    """Test authentication service."""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service with mock repository."""
        mock_repository = AsyncMock()
        return AuthService(mock_repository)
    
    async def test_successful_authentication(self, auth_service):
        """Test successful user authentication."""
        session = AsyncMock()
        request = AsyncMock()
        request.client.host = "192.168.1.1"
        
        # Mock user
        hashed_password = password_manager.hash_password("password123")
        user = User(
            id=1,
            email="test@example.com",
            hashed_password=hashed_password,
            is_active=True
        )
        auth_service.user_repository.get_by_email.return_value = user
        
        # Mock rate limiter
        with patch('neodyme.services.auth_service.rate_limiter') as mock_rate_limiter:
            mock_rate_limiter.check_rate_limit = AsyncMock()
            mock_rate_limiter.record_successful_attempt = AsyncMock()
            
            result = await auth_service.authenticate_user(
                session, "test@example.com", "password123", request
            )
        
        # Verify result
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["user"].email == "test@example.com"
        
        # Verify rate limiter was called
        mock_rate_limiter.record_successful_attempt.assert_called_once()
    
    async def test_failed_authentication(self, auth_service):
        """Test failed authentication with wrong password."""
        session = AsyncMock()
        request = AsyncMock()
        request.client.host = "192.168.1.1"
        
        # Mock user with different password
        hashed_password = password_manager.hash_password("different_password")
        user = User(
            id=1,
            email="test@example.com",
            hashed_password=hashed_password,
            is_active=True
        )
        auth_service.user_repository.get_by_email.return_value = user
        
        # Mock rate limiter
        with patch('neodyme.services.auth_service.rate_limiter') as mock_rate_limiter:
            mock_rate_limiter.check_rate_limit = AsyncMock()
            mock_rate_limiter.record_failed_attempt = AsyncMock()
            
            with pytest.raises(SecurityError) as exc_info:
                await auth_service.authenticate_user(
                    session, "test@example.com", "wrong_password", request
                )
        
        # Verify error
        assert exc_info.value.error_code == ErrorCode.INVALID_CREDENTIALS
        
        # Verify failed attempt was recorded
        mock_rate_limiter.record_failed_attempt.assert_called_once()
    
    async def test_authentication_nonexistent_user(self, auth_service):
        """Test authentication with non-existent user."""
        session = AsyncMock()
        request = AsyncMock()
        
        # Mock no user found
        auth_service.user_repository.get_by_email.return_value = None
        
        with patch('neodyme.services.auth_service.rate_limiter') as mock_rate_limiter:
            mock_rate_limiter.check_rate_limit = AsyncMock()
            
            with pytest.raises(SecurityError) as exc_info:
                await auth_service.authenticate_user(
                    session, "nonexistent@example.com", "password", request
                )
        
        assert exc_info.value.error_code == ErrorCode.INVALID_CREDENTIALS
        assert "Invalid email or password" in exc_info.value.user_message

@pytest.mark.asyncio
class TestRateLimiting:
    """Test rate limiting functionality."""
    
    async def test_rate_limit_allows_normal_usage(self):
        """Test that normal usage is allowed."""
        from neodyme.core.rate_limiting import RateLimiter
        
        rate_limiter = RateLimiter()
        request = AsyncMock()
        request.client.host = "192.168.1.1"
        request.headers = {}
        
        # Should allow normal number of attempts
        for _ in range(3):
            await rate_limiter.check_rate_limit(request, max_attempts=5, window_minutes=15)
    
    async def test_rate_limit_blocks_excessive_attempts(self):
        """Test that excessive attempts are blocked."""
        from neodyme.core.rate_limiting import RateLimiter
        from fastapi import HTTPException
        
        rate_limiter = RateLimiter()
        request = AsyncMock()
        request.client.host = "192.168.1.1"
        request.headers = {}
        
        # Make maximum allowed attempts
        for _ in range(5):
            await rate_limiter.check_rate_limit(request, max_attempts=5, window_minutes=15)
        
        # Next attempt should be blocked
        with pytest.raises(HTTPException) as exc_info:
            await rate_limiter.check_rate_limit(request, max_attempts=5, window_minutes=15)
        
        assert exc_info.value.status_code == 429
        assert "Too many attempts" in exc_info.value.detail
```

**Why comprehensive security testing is essential:**

- **Password security verification** - Tests ensure passwords are actually hashed securely and strength validation works
- **Token lifecycle testing** - Verifies that tokens are created, verified, and expire correctly
- **Authentication flow testing** - Ensures the complete authentication process works under various conditions
- **Rate limiting validation** - Confirms that brute force protection actually blocks attacks
- **Error handling verification** - Tests that security errors provide appropriate information without leaking sensitive data

## What You've Learned

By the end of this chapter, you understand:

✅ **Why security theater fails against real attacks** - and how professional security provides actual protection through defense in depth  
✅ **Password security fundamentals** - including bcrypt hashing, strength validation, and timing attack protection  
✅ **JWT token management** - creating, verifying, and refreshing tokens securely while preventing common attacks  
✅ **Rate limiting and attack prevention** - protecting against brute force attacks and resource exhaustion  
✅ **Authorization and permission systems** - controlling access to resources with fine-grained permissions  
✅ **Secure API endpoint design** - implementing endpoints that are protected against unauthorized access  

More importantly, you've built a security system that protects against real-world attacks while maintaining usability and performance.

## Building Blocks for Next Chapters

This security foundation gives us:
- **HTTP handling** ← Chapter 1: FastAPI basics
- **Data persistence** ← Chapter 2: Database integration  
- **Input validation** ← Chapter 3: Request/response validation
- **Schema evolution** ← Chapter 4: Database migrations
- **Clean architecture** ← Chapter 5: Service layer organization
- **Error handling** ← Chapter 6: Professional error management
- **Security** ← You are here
- **Configuration** ← Chapter 8: Environment-aware configuration management

## Exercises

1. **Implement password reset** - Add secure password reset with time-limited tokens
2. **Add two-factor authentication** - Implement TOTP-based 2FA for enhanced security
3. **Create API key authentication** - Add API key support for service-to-service authentication
4. **Build session management** - Add session tracking and device management
5. **Implement OAuth integration** - Add Google/GitHub OAuth for social login

## Resources for Deeper Learning

### Authentication and Security Fundamentals
- **OWASP Authentication Guide**: Comprehensive authentication security practices - https://owasp.org/www-project-authentication-cheat-sheet/
- **JWT Best Practices**: Secure JWT implementation guidelines - https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/
- **Password Hashing Guide**: Why and how to hash passwords securely - https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### Security Implementation
- **FastAPI Security Documentation**: Framework-specific security patterns - https://fastapi.tiangolo.com/tutorial/security/
- **Python Cryptography**: Secure cryptographic operations in Python - https://cryptography.io/en/latest/
- **Passlib Documentation**: Password hashing library best practices - https://passlib.readthedocs.io/en/stable/

### Attack Prevention
- **Rate Limiting Strategies**: Preventing abuse and attacks - https://cloud.google.com/architecture/rate-limiting-strategies-techniques
- **OWASP Top 10**: Common web application security risks - https://owasp.org/www-project-top-ten/
- **Web Security Academy**: Interactive security learning - https://portswigger.net/web-security

### Authorization and Access Control
- **RBAC vs ABAC**: Role-based vs attribute-based access control - https://www.okta.com/identity-101/role-based-access-control-vs-attribute-based-access-control/
- **Principle of Least Privilege**: Security through minimal access - https://www.cisa.gov/uscert/bsi/articles/knowledge/principles/least-privilege
- **OAuth 2.0 Security**: Modern authorization patterns - https://oauth.net/2/

### Why These Resources Matter
- **Security fundamentals**: Understanding core security principles prevents you from making common mistakes that lead to breaches
- **Attack awareness**: Learning about attack vectors helps you design defenses against real threats, not theoretical ones  
- **Implementation guidance**: Security is one area where following established patterns is critical - don't innovate on security basics
- **Compliance understanding**: Many industries have security requirements that proper authentication and authorization help satisfy

**Pro Tip**: Start with OWASP resources to understand common vulnerabilities, then focus on proper implementation of authentication and authorization patterns before adding advanced features.

## Next: Configuration Management

You have a secure application that protects against real attacks, but now you need to deploy it across different environments. How do you manage database URLs, API keys, and security settings across development, staging, and production? How do you keep secrets secure while making configuration maintainable?

In Chapter 8, we'll explore configuration management that works reliably across all deployment environments.

```python
# Preview of Chapter 8
class Settings(BaseSettings):
    """Environment-aware configuration with validation."""
    
    # Database
    database_url: PostgresDsn
    
    # Security
    secret_key: SecretStr
    jwt_algorithm: str = "HS256"
    
    # External Services
    email_smtp_host: str
    email_smtp_port: int = 587
    email_username: str
    email_password: SecretStr
    
    class Config:
        env_file = ".env"
        case_sensitive = False
```

We'll explore how to build configuration systems that prevent deployment errors while keeping sensitive information secure.
