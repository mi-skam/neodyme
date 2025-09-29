---
title: "Chapter 11"
weight: 11
type: docs
---
# Chapter 11: "I Need to Monitor and Debug Production Like a Professional"

Your neodyme application is running beautifully in production. Clean architecture, comprehensive error handling, secure authentication—everything you've built is working exactly as designed. Then at 3 AM, you get the call: "The application is down, users can't register, and we have no idea why."

You frantically check the server. The application is running. Database connections look fine. No obvious errors in the basic logs. But users are still reporting problems, and you're debugging blind with nothing but basic HTTP access logs and generic error messages.

This is the moment every production application faces: **when things go wrong, how quickly can you understand what happened?** The difference between systems that fail gracefully and those that create 3 AM panic calls isn't whether they have bugs—it's whether they provide the observability needed to debug issues quickly.

## The Problem: Production Applications as Black Boxes

Let me ask you: Have you ever spent hours debugging an issue that could have been solved in minutes with better logging? If so, you've experienced the pain of insufficient observability.

Here's what debugging looks like without proper monitoring:

```python
# What you see in basic logs
[2024-03-15 03:15:42] INFO: Starting user registration
[2024-03-15 03:15:43] ERROR: Registration failed
[2024-03-15 03:15:44] INFO: Starting user registration  
[2024-03-15 03:15:45] ERROR: Registration failed
[2024-03-15 03:15:46] ERROR: Registration failed

# What you need to debug
# - Which users are affected?
# - What specific step is failing?
# - Is this a database issue, email service issue, or validation problem?
# - When did this pattern start?
# - Are there any commonalities between failures?
```

**Why basic logging creates debugging nightmares:**

- **No context correlation** - You can't connect log entries to specific user requests or business operations
- **Missing performance data** - No insight into response times, database query performance, or external service latency
- **Insufficient error details** - Generic error messages don't provide enough information to understand root causes
- **No operational metrics** - You can't distinguish between isolated incidents and systematic problems
- **Reactive debugging only** - You discover problems only after users report them, not before they impact the business
- **Time-consuming investigation** - Every issue requires manual log analysis and hypothesis testing

The fundamental problem is that **applications need to tell you what they're doing**, not just when they fail.

## Why Basic Monitoring Isn't Enough

Traditional application monitoring looks like this:

```bash
# Basic server monitoring
CPU: 45%
Memory: 60% 
Disk: 30%
Network: Normal

# Basic HTTP logs
192.168.1.100 - - [15/Mar/2024:03:15:42] "POST /users/ HTTP/1.1" 500 45
192.168.1.101 - - [15/Mar/2024:03:15:43] "POST /users/ HTTP/1.1" 500 45
192.168.1.102 - - [15/Mar/2024:03:15:44] "POST /users/ HTTP/1.1" 500 45
```

**This approach fails because:**

- **System metrics don't reveal application problems** - CPU and memory usage look normal even when business logic is completely broken
- **HTTP status codes hide business context** - A 500 error could be a database timeout, email service failure, or validation issue
- **No user journey tracking** - You can't understand how individual user sessions progress through your application
- **Missing dependencies visibility** - External service failures are invisible until they cause user-facing errors
- **No performance baselines** - You can't distinguish between normal slowness and performance degradation

## The Observability Solution: Applications That Explain Themselves

Professional observability makes applications self-documenting through three pillars: **logs**, **metrics**, and **traces**. Here's how neodyme implements comprehensive observability:

### Structured Logging: Making Logs Machine-Readable

```python
# core/logging.py - Structured logging configuration
import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict, Optional
from contextvars import ContextVar
from uuid import uuid4

# Context variables for request correlation
request_id_var: ContextVar[str] = ContextVar('request_id', default='')
user_id_var: ContextVar[Optional[int]] = ContextVar('user_id', default=None)

class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        
        # Base log data
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add request context if available
        request_id = request_id_var.get('')
        if request_id:
            log_data["request_id"] = request_id
            
        user_id = user_id_var.get(None)
        if user_id:
            log_data["user_id"] = user_id
        
        # Add exception information
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }
        
        # Add extra context from log calls
        if hasattr(record, 'context'):
            log_data["context"] = record.context
            
        return json.dumps(log_data)

def setup_logging():
    """Configure structured logging for the application."""
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Console handler with structured formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(StructuredFormatter())
    
    # Remove default handlers
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    
    # Configure third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

# Structured logging helpers
def log_with_context(logger: logging.Logger, level: int, message: str, **context):
    """Log with additional context data."""
    extra = {"context": context}
    logger.log(level, message, extra=extra)

def log_user_action(action: str, user_id: int, **context):
    """Log user actions with consistent format."""
    logger = logging.getLogger("neodyme.user_actions")
    log_with_context(
        logger, 
        logging.INFO, 
        f"User action: {action}",
        user_id=user_id,
        action=action,
        **context
    )

def log_external_service_call(service: str, operation: str, duration: float, success: bool, **context):
    """Log external service calls with performance data."""
    logger = logging.getLogger("neodyme.external_services")
    log_with_context(
        logger,
        logging.INFO,
        f"External service call: {service}.{operation}",
        service=service,
        operation=operation,
        duration_ms=round(duration * 1000, 2),
        success=success,
        **context
    )
```

**Why structured logging is essential for production debugging:**

- **Machine-readable format** - JSON logs can be automatically parsed, searched, and analyzed by log aggregation tools
- **Request correlation** - Request IDs connect all log entries for a single user action, making debugging exponentially faster
- **Rich context** - Every log entry includes relevant business and technical context for understanding what happened
- **Consistent format** - Standardized log structure makes it easy to build dashboards and alerts
- **Performance tracking** - Duration and success metrics for external calls reveal performance bottlenecks immediately

### Request Tracking Middleware

```python
# middleware/request_tracking.py - Request correlation and timing
import time
from uuid import uuid4
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from neodyme.core.logging import request_id_var, user_id_var, log_with_context
import logging

logger = logging.getLogger("neodyme.requests")

class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware for request correlation and performance tracking."""
    
    async def dispatch(self, request: Request, call_next):
        """Track request lifecycle with correlation and timing."""
        
        # Generate unique request ID
        request_id = str(uuid4())
        request_id_var.set(request_id)
        
        # Start timing
        start_time = time.time()
        
        # Extract user ID from token if available
        user_id = await self._extract_user_id(request)
        if user_id:
            user_id_var.set(user_id)
        
        # Log request start
        log_with_context(
            logger,
            logging.INFO,
            "Request started",
            method=request.method,
            url=str(request.url),
            client_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "unknown"),
            content_length=request.headers.get("content-length"),
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log successful request
            log_with_context(
                logger,
                logging.INFO,
                "Request completed",
                status_code=response.status_code,
                duration_ms=round(duration * 1000, 2),
                response_size=response.headers.get("content-length"),
            )
            
            # Add correlation headers to response
            response.headers["X-Request-ID"] = request_id
            return response
            
        except Exception as e:
            # Calculate duration for failed requests
            duration = time.time() - start_time
            
            # Log failed request
            log_with_context(
                logger,
                logging.ERROR,
                "Request failed",
                error_type=type(e).__name__,
                error_message=str(e),
                duration_ms=round(duration * 1000, 2),
            )
            
            raise
    
    async def _extract_user_id(self, request: Request) -> Optional[int]:
        """Extract user ID from JWT token if present."""
        try:
            # This would integrate with your auth system
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                # Decode JWT and extract user ID
                # Implementation depends on your auth setup
                pass
        except Exception:
            # Don't fail requests due to user ID extraction issues
            pass
        return None
```

**Why request tracking transforms debugging:**

- **Request correlation** - Every log entry for a single user action is connected by request ID, making it trivial to trace entire workflows
- **Performance visibility** - Request duration and external service timing immediately reveal performance bottlenecks
- **User context** - Knowing which user triggered an issue helps reproduce problems and understand impact
- **Client information** - User agent and IP data help identify client-specific issues or attack patterns

### Service-Level Instrumentation

```python
# services/instrumented_user_service.py - Service layer with observability
import time
import logging
from typing import Optional
from neodyme.core.logging import log_with_context, log_user_action, log_external_service_call
from neodyme.services.user_service import UserService as BaseUserService

logger = logging.getLogger("neodyme.user_service")

class UserService(BaseUserService):
    """User service with comprehensive instrumentation."""
    
    async def register_user(
        self, 
        session: AsyncSession, 
        user_data: UserCreate,
        ip_address: str
    ) -> UserPublic:
        """Register user with full observability."""
        
        log_with_context(
            logger,
            logging.INFO,
            "User registration started",
            email=user_data.email,
            ip_address=ip_address,
            registration_method="email"
        )
        
        try:
            # Step 1: Check for existing user
            existing_user = await self._check_existing_user(session, user_data.email)
            
            # Step 2: Create user
            user = await self._create_user_record(session, user_data)
            
            # Step 3: Handle side effects
            await self._handle_registration_side_effects(user, ip_address)
            
            # Log successful registration
            log_user_action(
                "user_registered",
                user.id,
                email=user.email,
                ip_address=ip_address,
                registration_duration_ms=0  # Would calculate actual duration
            )
            
            log_with_context(
                logger,
                logging.INFO,
                "User registration completed successfully",
                user_id=user.id,
                email=user.email
            )
            
            return UserPublic.model_validate(user)
            
        except Exception as e:
            log_with_context(
                logger,
                logging.ERROR,
                "User registration failed",
                email=user_data.email,
                ip_address=ip_address,
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise
    
    async def _check_existing_user(self, session: AsyncSession, email: str) -> Optional[User]:
        """Check for existing user with timing."""
        start_time = time.time()
        
        try:
            existing_user = await self.user_repository.get_by_email(session, email=email)
            duration = time.time() - start_time
            
            log_with_context(
                logger,
                logging.DEBUG,
                "Database query: check existing user",
                email=email,
                duration_ms=round(duration * 1000, 2),
                found=existing_user is not None
            )
            
            return existing_user
            
        except Exception as e:
            duration = time.time() - start_time
            log_with_context(
                logger,
                logging.ERROR,
                "Database query failed: check existing user",
                email=email,
                duration_ms=round(duration * 1000, 2),
                error=str(e)
            )
            raise
    
    async def _handle_registration_side_effects(self, user: User, ip_address: str) -> None:
        """Handle side effects with individual instrumentation."""
        
        # Email sending with timing
        await self._send_welcome_email_instrumented(user)
        
        # Analytics tracking with timing
        await self._track_analytics_instrumented(user)
        
        # Audit logging with timing
        await self._log_audit_instrumented(user, ip_address)
    
    async def _send_welcome_email_instrumented(self, user: User) -> None:
        """Send welcome email with comprehensive logging."""
        start_time = time.time()
        
        try:
            await self.email_service.send_welcome_email(user)
            duration = time.time() - start_time
            
            log_external_service_call(
                "email",
                "send_welcome",
                duration,
                True,
                user_id=user.id,
                email=user.email
            )
            
        except Exception as e:
            duration = time.time() - start_time
            
            log_external_service_call(
                "email",
                "send_welcome",
                duration,
                False,
                user_id=user.id,
                email=user.email,
                error=str(e)
            )
            
            # Don't fail registration for email issues
            log_with_context(
                logger,
                logging.WARNING,
                "Welcome email failed but registration continues",
                user_id=user.id,
                error=str(e)
            )
    
    async def _track_analytics_instrumented(self, user: User) -> None:
        """Track analytics with timing and error handling."""
        start_time = time.time()
        
        try:
            await self.analytics_service.track_user_registration(user)
            duration = time.time() - start_time
            
            log_external_service_call(
                "analytics",
                "track_registration",
                duration,
                True,
                user_id=user.id
            )
            
        except Exception as e:
            duration = time.time() - start_time
            
            log_external_service_call(
                "analytics",
                "track_registration",
                duration,
                False,
                user_id=user.id,
                error=str(e)
            )
            
            log_with_context(
                logger,
                logging.WARNING,
                "Analytics tracking failed but registration continues",
                user_id=user.id,
                error=str(e)
            )
```

**Why service-level instrumentation provides operational insight:**

- **Business operation tracking** - Every important business action is logged with context and timing
- **Dependency performance** - External service call timing reveals performance bottlenecks immediately
- **Failure isolation** - You can see exactly which step in a complex workflow failed and why
- **Impact assessment** - Logs show whether failures affected core operations or just side effects

### Application Metrics Collection

```python
# core/metrics.py - Application performance metrics
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import asyncio
import logging

logger = logging.getLogger("neodyme.metrics")

@dataclass
class MetricPoint:
    """Individual metric measurement."""
    name: str
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)

class MetricsCollector:
    """In-memory metrics collection for application monitoring."""
    
    def __init__(self):
        self.metrics: Dict[str, list[MetricPoint]] = {}
        self.counters: Dict[str, int] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, list[float]] = {}
    
    def increment(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter metric."""
        key = self._build_key(name, tags or {})
        self.counters[key] = self.counters.get(key, 0) + value
        
        self._store_metric(MetricPoint(
            name=name,
            value=self.counters[key],
            timestamp=datetime.utcnow(),
            tags=tags or {}
        ))
    
    def gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge metric value."""
        key = self._build_key(name, tags or {})
        self.gauges[key] = value
        
        self._store_metric(MetricPoint(
            name=name,
            value=value,
            timestamp=datetime.utcnow(),
            tags=tags or {}
        ))
    
    def histogram(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record a histogram value (for timing, sizes, etc.)."""
        key = self._build_key(name, tags or {})
        if key not in self.histograms:
            self.histograms[key] = []
        self.histograms[key].append(value)
        
        self._store_metric(MetricPoint(
            name=name,
            value=value,
            timestamp=datetime.utcnow(),
            tags=tags or {}
        ))
    
    def timing(self, name: str, duration: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record timing information."""
        self.histogram(f"{name}.duration", duration * 1000, tags)  # Convert to milliseconds
    
    def _build_key(self, name: str, tags: Dict[str, str]) -> str:
        """Build metric key with tags."""
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}[{tag_str}]"
    
    def _store_metric(self, metric: MetricPoint) -> None:
        """Store metric point for reporting."""
        if metric.name not in self.metrics:
            self.metrics[metric.name] = []
        
        self.metrics[metric.name].append(metric)
        
        # Keep only recent metrics (last hour)
        cutoff = datetime.utcnow() - timedelta(hours=1)
        self.metrics[metric.name] = [
            m for m in self.metrics[metric.name] 
            if m.timestamp > cutoff
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary for health checks."""
        now = datetime.utcnow()
        last_minute = now - timedelta(minutes=1)
        
        summary = {
            "timestamp": now.isoformat(),
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
        }
        
        # Calculate histogram summaries
        histogram_summaries = {}
        for key, values in self.histograms.items():
            if values:
                recent_values = [
                    v for v in values[-100:]  # Last 100 measurements
                ]
                if recent_values:
                    histogram_summaries[key] = {
                        "count": len(recent_values),
                        "min": min(recent_values),
                        "max": max(recent_values),
                        "avg": sum(recent_values) / len(recent_values),
                        "p95": self._percentile(recent_values, 95),
                        "p99": self._percentile(recent_values, 99)
                    }
        
        summary["histograms"] = histogram_summaries
        return summary
    
    def _percentile(self, values: list[float], percentile: int) -> float:
        """Calculate percentile value."""
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile / 100)
        return sorted_values[min(index, len(sorted_values) - 1)]

# Global metrics collector
metrics = MetricsCollector()

# Metrics helpers
def time_operation(operation_name: str, tags: Optional[Dict[str, str]] = None):
    """Context manager for timing operations."""
    class TimingContext:
        def __init__(self, name: str, tags: Optional[Dict[str, str]]):
            self.name = name
            self.tags = tags or {}
            self.start_time = None
        
        def __enter__(self):
            self.start_time = time.time()
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            if self.start_time:
                duration = time.time() - self.start_time
                success = exc_type is None
                final_tags = {**self.tags, "success": str(success)}
                metrics.timing(self.name, duration, final_tags)
    
    return TimingContext(operation_name, tags)

def track_user_action(action: str, user_id: int, success: bool = True) -> None:
    """Track user actions for business metrics."""
    metrics.increment(
        "user_actions",
        tags={
            "action": action,
            "success": str(success)
        }
    )
    
    if success:
        metrics.increment("user_actions.success", tags={"action": action})
    else:
        metrics.increment("user_actions.failure", tags={"action": action})

def track_external_service(service: str, operation: str, duration: float, success: bool) -> None:
    """Track external service calls."""
    metrics.timing(
        "external_service.duration",
        duration,
        tags={
            "service": service,
            "operation": operation,
            "success": str(success)
        }
    )
    
    metrics.increment(
        "external_service.calls",
        tags={
            "service": service,
            "operation": operation,
            "success": str(success)
        }
    )
```

**Why application metrics enable proactive operations:**

- **Performance baselines** - Historical timing data helps identify when performance degrades from normal levels
- **Business KPIs** - User action tracking provides insight into business metrics like registration rates and feature usage
- **Dependency monitoring** - External service timing reveals which dependencies are slow or failing
- **Capacity planning** - Resource usage trends help predict when scaling is needed before problems occur

### Health Check Implementation

```python
# routes/health.py - Comprehensive health monitoring
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
import asyncio
import time
from datetime import datetime
import logging

from neodyme.core.metrics import metrics
from neodyme.core.database import get_async_session
from neodyme.core.config import settings

router = APIRouter(prefix="/health", tags=["health"])
logger = logging.getLogger("neodyme.health")

@router.get("/", response_model=Dict[str, Any])
async def basic_health() -> Dict[str, Any]:
    """Basic health check for load balancers."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.app_version
    }

@router.get("/detailed", response_model=Dict[str, Any])
async def detailed_health(
    session = Depends(get_async_session)
) -> Dict[str, Any]:
    """Detailed health check with dependency verification."""
    
    health_data = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.app_version,
        "checks": {}
    }
    
    overall_healthy = True
    
    # Database health check
    db_health = await _check_database_health(session)
    health_data["checks"]["database"] = db_health
    if not db_health["healthy"]:
        overall_healthy = False
    
    # External services health
    email_health = await _check_email_service_health()
    health_data["checks"]["email_service"] = email_health
    if not email_health["healthy"]:
        # Email failures don't make the app unhealthy, just degraded
        health_data["status"] = "degraded"
    
    analytics_health = await _check_analytics_service_health()
    health_data["checks"]["analytics_service"] = analytics_health
    if not analytics_health["healthy"]:
        health_data["status"] = "degraded"
    
    # Application metrics
    health_data["metrics"] = metrics.get_summary()
    
    # System resources
    health_data["system"] = await _get_system_info()
    
    if not overall_healthy:
        health_data["status"] = "unhealthy"
        raise HTTPException(status_code=503, detail=health_data)
    
    return health_data

async def _check_database_health(session) -> Dict[str, Any]:
    """Check database connectivity and performance."""
    start_time = time.time()
    
    try:
        # Simple query to test connectivity
        result = await session.execute("SELECT 1")
        await result.fetchone()
        
        duration = time.time() - start_time
        
        # Check if database is responsive (< 100ms for simple query)
        healthy = duration < 0.1
        
        return {
            "healthy": healthy,
            "response_time_ms": round(duration * 1000, 2),
            "status": "connected" if healthy else "slow"
        }
        
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Database health check failed: {e}")
        
        return {
            "healthy": False,
            "response_time_ms": round(duration * 1000, 2),
            "status": "error",
            "error": str(e)
        }

async def _check_email_service_health() -> Dict[str, Any]:
    """Check email service connectivity."""
    start_time = time.time()
    
    try:
        # Test SMTP connection without sending email
        import smtplib
        
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=5) as server:
            server.noop()  # No-operation command to test connection
        
        duration = time.time() - start_time
        
        return {
            "healthy": True,
            "response_time_ms": round(duration * 1000, 2),
            "status": "connected"
        }
        
    except Exception as e:
        duration = time.time() - start_time
        logger.warning(f"Email service health check failed: {e}")
        
        return {
            "healthy": False,
            "response_time_ms": round(duration * 1000, 2),
            "status": "error",
            "error": str(e)
        }

async def _check_analytics_service_health() -> Dict[str, Any]:
    """Check analytics service connectivity."""
    start_time = time.time()
    
    try:
        import httpx
        
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Make a simple health check request to analytics service
            response = await client.get(f"{settings.analytics_base_url}/health")
            response.raise_for_status()
        
        duration = time.time() - start_time
        
        return {
            "healthy": True,
            "response_time_ms": round(duration * 1000, 2),
            "status": "connected"
        }
        
    except Exception as e:
        duration = time.time() - start_time
        logger.warning(f"Analytics service health check failed: {e}")
        
        return {
            "healthy": False,
            "response_time_ms": round(duration * 1000, 2),
            "status": "error",
            "error": str(e)
        }

async def _get_system_info() -> Dict[str, Any]:
    """Get basic system resource information."""
    try:
        import psutil
        
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "load_average": psutil.getloadavg()[0]  # 1-minute load average
        }
    except ImportError:
        return {"error": "psutil not available"}
    except Exception as e:
        return {"error": f"System info unavailable: {e}"}

@router.get("/metrics", response_model=Dict[str, Any])
async def get_metrics() -> Dict[str, Any]:
    """Get application metrics for monitoring systems."""
    return metrics.get_summary()
```

**Why comprehensive health checks enable reliable operations:**

- **Load balancer integration** - Basic health checks ensure traffic only goes to healthy instances
- **Dependency monitoring** - External service health checks reveal upstream problems immediately
- **Performance baselines** - Response time metrics help identify degrading performance before it becomes critical
- **Operational dashboards** - Structured health data can be automatically graphed and alerted on

### Error Alerting and Monitoring

```python
# core/alerting.py - Error pattern detection and alerting
import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass
import asyncio

logger = logging.getLogger("neodyme.alerting")

@dataclass
class ErrorPattern:
    """Detected error pattern requiring attention."""
    error_type: str
    count: int
    first_seen: datetime
    last_seen: datetime
    affected_users: set[int]
    sample_errors: List[Dict[str, Any]]

class ErrorMonitor:
    """Monitor error patterns and trigger alerts."""
    
    def __init__(self):
        self.error_counts = defaultdict(int)
        self.error_history = defaultdict(lambda: deque(maxlen=100))
        self.user_errors = defaultdict(set)
        self.alert_cooldowns = {}  # Prevent alert spam
    
    def record_error(
        self, 
        error_type: str, 
        user_id: int = None, 
        context: Dict[str, Any] = None
    ) -> None:
        """Record error occurrence for pattern detection."""
        
        now = datetime.utcnow()
        error_data = {
            "timestamp": now,
            "error_type": error_type,
            "user_id": user_id,
            "context": context or {}
        }
        
        # Track error counts
        self.error_counts[error_type] += 1
        self.error_history[error_type].append(error_data)
        
        if user_id:
            self.user_errors[error_type].add(user_id)
        
        # Check for alert conditions
        asyncio.create_task(self._check_alert_conditions(error_type))
    
    async def _check_alert_conditions(self, error_type: str) -> None:
        """Check if error patterns warrant alerts."""
        
        now = datetime.utcnow()
        recent_cutoff = now - timedelta(minutes=5)
        
        # Get recent errors of this type
        recent_errors = [
            e for e in self.error_history[error_type]
            if e["timestamp"] > recent_cutoff
        ]
        
        if not recent_errors:
            return
        
        # Check alert conditions
        should_alert = False
        alert_reason = ""
        
        # Condition 1: High error rate (>10 errors in 5 minutes)
        if len(recent_errors) > 10:
            should_alert = True
            alert_reason = f"High error rate: {len(recent_errors)} errors in 5 minutes"
        
        # Condition 2: Multiple users affected (>5 users)
        recent_users = {e["user_id"] for e in recent_errors if e["user_id"]}
        if len(recent_users) > 5:
            should_alert = True
            alert_reason = f"Multiple users affected: {len(recent_users)} users"
        
        # Condition 3: Critical error types (always alert)
        critical_errors = ["DATABASE_ERROR", "AUTHENTICATION_FAILURE", "SECURITY_VIOLATION"]
        if error_type in critical_errors:
            should_alert = True
            alert_reason = f"Critical error: {error_type}"
        
        # Send alert if conditions met and not in cooldown
        if should_alert:
            await self._send_alert_if_needed(error_type, alert_reason, recent_errors)
    
    async def _send_alert_if_needed(
        self, 
        error_type: str, 
        reason: str, 
        recent_errors: List[Dict[str, Any]]
    ) -> None:
        """Send alert if not in cooldown period."""
        
        now = datetime.utcnow()
        cooldown_key = f"{error_type}:{reason}"
        
        # Check cooldown (don't spam alerts)
        if cooldown_key in self.alert_cooldowns:
            last_alert = self.alert_cooldowns[cooldown_key]
            if now - last_alert < timedelta(minutes=15):
                return  # Still in cooldown
        
        # Record alert time
        self.alert_cooldowns[cooldown_key] = now
        
        # Create alert data
        alert_data = {
            "alert_type": "error_pattern",
            "error_type": error_type,
            "reason": reason,
            "timestamp": now.isoformat(),
            "recent_error_count": len(recent_errors),
            "total_error_count": self.error_counts[error_type],
            "affected_users": len({e["user_id"] for e in recent_errors if e["user_id"]}),
            "sample_errors": recent_errors[:3]  # Include sample errors
        }
        
        # Send alert (in production, integrate with PagerDuty, Slack, etc.)
        await self._dispatch_alert(alert_data)
    
    async def _dispatch_alert(self, alert_data: Dict[str, Any]) -> None:
        """Dispatch alert to appropriate channels."""
        
        # Log alert for operators
        logger.critical(
            f"ERROR ALERT: {alert_data['reason']}",
            extra={"alert_data": alert_data}
        )
        
        # In production, send to:
        # - PagerDuty for critical alerts
        # - Slack for warning alerts  
        # - Email for summary reports
        # - Dashboard for real-time monitoring
        
        print(f"🚨 ALERT: {alert_data['reason']} ({alert_data['error_type']})")
        print(f"   Recent errors: {alert_data['recent_error_count']}")
        print(f"   Affected users: {alert_data['affected_users']}")

# Global error monitor
error_monitor = ErrorMonitor()

# Integration with exception handler
async def track_error_for_monitoring(error_type: str, user_id: int = None, context: Dict[str, Any] = None):
    """Track error for monitoring and alerting."""
    error_monitor.record_error(error_type, user_id, context)
```

**Why error monitoring enables proactive incident response:**

- **Pattern detection** - Automatically identifies when error rates exceed normal levels, catching issues before they become critical
- **User impact assessment** - Tracks how many users are affected by each error type, helping prioritize response efforts
- **Alert deduplication** - Cooldown periods prevent alert spam while ensuring important issues aren't missed
- **Context preservation** - Sample errors provide immediate debugging context without overwhelming operators

## Observability Integration in Service Layer

```python
# services/monitored_user_service.py - Complete observability integration
from neodyme.core.logging import log_with_context, log_user_action
from neodyme.core.metrics import metrics, time_operation, track_user_action, track_external_service
from neodyme.core.alerting import track_error_for_monitoring

class UserService:
    """User service with complete observability integration."""
    
    async def register_user(
        self, 
        session: AsyncSession, 
        user_data: UserCreate,
        ip_address: str
    ) -> UserPublic:
        """Register user with comprehensive observability."""
        
        with time_operation("user_registration", {"method": "email"}):
            try:
                # Log registration start
                log_with_context(
                    logger,
                    logging.INFO,
                    "User registration started",
                    email=user_data.email,
                    ip_address=ip_address
                )
                
                # Increment registration attempts counter
                metrics.increment("user_registration.attempts")
                
                # Check for existing user
                with time_operation("user_registration.check_existing"):
                    existing_user = await self.user_repository.get_by_email(
                        session, email=user_data.email
                    )
                    
                if existing_user:
                    # Track business metric
                    track_user_action("registration_duplicate", None, False)
                    
                    # Track for monitoring
                    await track_error_for_monitoring(
                        "EMAIL_ALREADY_EXISTS",
                        context={"email": user_data.email, "ip_address": ip_address}
                    )
                    
                    raise EmailAlreadyExistsError(user_data.email)
                
                # Create user
                with time_operation("user_registration.create_user"):
                    user = await self.user_repository.create(session, obj_in=user_data)
                
                # Track successful creation
                track_user_action("user_created", user.id, True)
                metrics.increment("user_registration.success")
                
                # Handle side effects (measured individually)
                await self._handle_monitored_side_effects(user, ip_address)
                
                # Log successful completion
                log_user_action(
                    "user_registered",
                    user.id,
                    email=user.email,
                    ip_address=ip_address
                )
                
                return UserPublic.model_validate(user)
                
            except EmailAlreadyExistsError:
                # Expected business error - track but don't alert
                metrics.increment("user_registration.duplicate")
                raise
                
            except Exception as e:
                # Unexpected error - track for alerting
                metrics.increment("user_registration.error")
                
                await track_error_for_monitoring(
                    "USER_REGISTRATION_ERROR",
                    context={
                        "email": user_data.email,
                        "ip_address": ip_address,
                        "error": str(e)
                    }
                )
                
                log_with_context(
                    logger,
                    logging.ERROR,
                    "User registration failed unexpectedly",
                    email=user_data.email,
                    error=str(e)
                )
                
                raise
    
    async def _handle_monitored_side_effects(self, user: User, ip_address: str) -> None:
        """Handle side effects with individual monitoring."""
        
        # Email service with monitoring
        start_time = time.time()
        try:
            await self.email_service.send_welcome_email(user)
            duration = time.time() - start_time
            track_external_service("email", "send_welcome", duration, True)
            
        except Exception as e:
            duration = time.time() - start_time
            track_external_service("email", "send_welcome", duration, False)
            
            # Track email service issues
            await track_error_for_monitoring(
                "EMAIL_SERVICE_ERROR",
                user.id,
                {"operation": "send_welcome", "error": str(e)}
            )
            
            log_with_context(
                logger,
                logging.WARNING,
                "Welcome email failed but registration continues",
                user_id=user.id,
                error=str(e)
            )
        
        # Analytics service with monitoring  
        start_time = time.time()
        try:
            await self.analytics_service.track_user_registration(user)
            duration = time.time() - start_time
            track_external_service("analytics", "track_registration", duration, True)
            
        except Exception as e:
            duration = time.time() - start_time
            track_external_service("analytics", "track_registration", duration, False)
            
            log_with_context(
                logger,
                logging.WARNING,
                "Analytics tracking failed but registration continues",
                user_id=user.id,
                error=str(e)
            )
```

**Why comprehensive service layer observability is transformative:**

- **End-to-end visibility** - Every step of complex workflows is measured and logged, making debugging trivial
- **Performance optimization** - Individual operation timing reveals exactly which steps are slow
- **Business intelligence** - User action tracking provides insight into feature usage and conversion rates
- **Proactive alerting** - Error patterns are detected automatically before they impact large numbers of users

## Testing Observability Implementation

```python
# tests/test_observability.py
import pytest
from unittest.mock import AsyncMock, patch
from neodyme.core.metrics import metrics
from neodyme.core.alerting import error_monitor
from neodyme.services.monitored_user_service import UserService

@pytest.mark.asyncio
async def test_user_registration_metrics():
    """Test that user registration records appropriate metrics."""
    
    # Reset metrics for clean test
    metrics.counters.clear()
    metrics.histograms.clear()
    
    # Setup service with mocks
    user_repository = AsyncMock()
    email_service = AsyncMock()
    analytics_service = AsyncMock()
    
    user_repository.get_by_email.return_value = None
    user_repository.create.return_value = User(
        id=1, email="test@example.com", full_name="Test User"
    )
    
    service = UserService(
        user_repository=user_repository,
        email_service=email_service,
        analytics_service=analytics_service
    )
    
    # Perform registration
    user_data = UserCreate(
        email="test@example.com",
        full_name="Test User",
        password="password123"
    )
    session = AsyncMock()
    
    await service.register_user(session, user_data, "192.168.1.1")
    
    # Verify metrics were recorded
    assert "user_registration.attempts" in [
        key.split('[')[0] for key in metrics.counters.keys()
    ]
    assert "user_registration.success" in [
        key.split('[')[0] for key in metrics.counters.keys()
    ]
    
    # Verify timing metrics were recorded
    timing_metrics = [key for key in metrics.histograms.keys() if "duration" in key]
    assert len(timing_metrics) > 0

@pytest.mark.asyncio
async def test_error_monitoring_triggers_alerts():
    """Test that error patterns trigger appropriate alerts."""
    
    # Reset error monitor
    error_monitor.error_counts.clear()
    error_monitor.error_history.clear()
    
    # Record multiple errors of the same type
    for i in range(12):  # Exceeds alert threshold of 10
        error_monitor.record_error(
            "EMAIL_SERVICE_ERROR",
            user_id=i,
            context={"attempt": i}
        )
    
    # Allow async alert processing
    await asyncio.sleep(0.1)
    
    # Verify error was recorded
    assert error_monitor.error_counts["EMAIL_SERVICE_ERROR"] == 12
    
    # In a real test, you would verify that alerts were sent
    # This would involve mocking the alert dispatch mechanism

@pytest.mark.asyncio
async def test_structured_logging_includes_context():
    """Test that structured logging includes proper context."""
    
    with patch('neodyme.core.logging.logger') as mock_logger:
        # Setup service
        user_repository = AsyncMock()
        email_service = AsyncMock()
        
        # Make email service fail
        email_service.send_welcome_email.side_effect = Exception("SMTP Error")
        
        service = UserService(
            user_repository=user_repository,
            email_service=email_service,
            analytics_service=AsyncMock()
        )
        
        # Try registration (should handle email failure gracefully)
        user_data = UserCreate(
            email="test@example.com",
            full_name="Test User",
            password="password123"
        )
        
        await service.register_user(AsyncMock(), user_data, "192.168.1.1")
        
        # Verify structured logging was called with context
        warning_calls = [
            call for call in mock_logger.warning.call_args_list
            if "Welcome email failed" in str(call)
        ]
        assert len(warning_calls) > 0

@pytest.mark.asyncio
async def test_health_check_detects_issues():
    """Test that health checks properly detect service issues."""
    
    from neodyme.routes.health import _check_email_service_health
    
    # Mock SMTP connection failure
    with patch('smtplib.SMTP') as mock_smtp:
        mock_smtp.side_effect = Exception("Connection refused")
        
        health_result = await _check_email_service_health()
        
        assert health_result["healthy"] is False
        assert "error" in health_result
        assert health_result["status"] == "error"
```

**Why testing observability is crucial:**

- **Metric accuracy** - Tests ensure that business metrics accurately reflect actual operations
- **Alert reliability** - Tests verify that alert conditions trigger appropriately without false positives
- **Log completeness** - Tests confirm that error scenarios include sufficient context for debugging
- **Health check validity** - Tests ensure health checks accurately reflect service status

## What You've Learned

By the end of this chapter, you understand:

✅ **Why basic logging creates debugging nightmares** - and how structured logging with correlation IDs makes debugging exponentially faster  
✅ **How comprehensive metrics enable proactive operations** - providing visibility into performance trends and business KPIs before problems become critical  
✅ **Why request tracking transforms production debugging** - connecting all log entries for a user action makes complex issue investigation trivial  
✅ **How error monitoring enables proactive incident response** - automatically detecting patterns and alerting on issues before they impact large numbers of users  
✅ **Why health checks enable reliable operations** - ensuring load balancers and monitoring systems understand actual application health  
✅ **How observability integration provides end-to-end visibility** - making every aspect of your application self-documenting and measurable  

More importantly, you've built observability that transforms your application from a black box into a system that explains its own behavior, enabling rapid debugging and proactive operations.

## Building Blocks for Next Chapters

This observability foundation gives us:
- **HTTP handling** ← Chapter 1: FastAPI basics
- **Data persistence** ← Chapter 2: Database integration  
- **Input validation** ← Chapter 3: Request/response validation
- **Schema evolution** ← Chapter 4: Database migrations
- **Clean architecture** ← Chapter 5: Service layer organization
- **Error handling** ← Chapter 6: Professional error management
- **Security** ← Chapter 7: Authentication and authorization
- **Configuration** ← Chapter 8: Environment management
- **Testing** ← Chapter 9: Comprehensive test strategies
- **Deployment** ← Chapter 10: Production deployment
- **Observability** ← You are here
- **Scaling** ← Chapter 12: Performance and scaling

## Exercises

1. **Add custom metrics** - Implement business-specific metrics for your domain (e.g., conversion rates, feature usage)
2. **Create alert rules** - Build alert conditions for different error types and business scenarios
3. **Implement distributed tracing** - Add trace IDs that follow requests across multiple services
4. **Build monitoring dashboards** - Create real-time dashboards showing key application metrics
5. **Add performance profiling** - Implement code-level performance monitoring to identify optimization opportunities

## Resources for Deeper Learning

### Observability Fundamentals
- **Observability Engineering**: Comprehensive guide to observability practices - https://www.honeycomb.io/blog/observability-engineering-101/
- **The Three Pillars of Observability**: Logs, metrics, and traces explained - https://peter.bourgon.org/blog/2017/02/21/metrics-tracing-and-logging.html
- **SRE Monitoring and Observability**: Google's approach to production monitoring - https://sre.google/sre-book/monitoring-distributed-systems/

### Structured Logging
- **Structured Logging Best Practices**: Making logs machine-readable and useful - https://www.honeycomb.io/blog/structured-logging-and-your-team/
- **Python Logging Configuration**: Advanced logging setup patterns - https://realpython.com/python-logging/
- **JSON Logging Standards**: Standardized log formats for better tooling - https://www.elastic.co/guide/en/ecs/current/index.html

### Metrics and Monitoring
- **Prometheus Monitoring**: Industry-standard metrics collection - https://prometheus.io/docs/introduction/overview/
- **RED Method**: Rate, Errors, Duration metrics for service monitoring - https://www.weave.works/blog/the-red-method-key-metrics-for-microservices-architecture/
- **USE Method**: Utilization, Saturation, Errors for resource monitoring - http://www.brendangregg.com/usemethod.html

### Production Debugging
- **Distributed Tracing**: Following requests across service boundaries - https://opentracing.io/docs/overview/what-is-tracing/
- **Error Tracking**: Effective error monitoring and alerting - https://sentry.io/for/error-monitoring/
- **Performance Monitoring**: Application performance management patterns - https://newrelic.com/platform/application-monitoring

### Why These Resources Matter
- **Observability principles**: Understanding the theory behind observability helps you implement it effectively
- **Structured data**: Learning structured logging and metrics enables building powerful monitoring tooling
- **Production practices**: SRE and DevOps practices provide proven patterns for reliable operations
- **Tooling integration**: Understanding how observability tools work helps you choose and configure them effectively

**Pro Tip**: Start with structured logging and basic metrics, then add distributed tracing and advanced alerting as your system grows in complexity.

## Next: Scaling Beyond One Machine

You have comprehensive observability that shows exactly how your application is performing, but now you're facing a new challenge: success. Your user base is growing, request volumes are increasing, and single-server deployment isn't enough anymore.

In Chapter 12, we'll explore scaling patterns that handle real-world load while maintaining the reliability and observability you've built.

```python
# Preview of Chapter 12
class CacheService:
    """High-performance caching for frequently accessed data."""
    
    async def get_user_profile(self, user_id: int) -> Optional[UserProfile]:
        """Get user profile with multi-layer caching."""
        # Check in-memory cache
        # Check Redis cache
        # Fall back to database
        # Update caches appropriately
        pass

class BackgroundJobProcessor:
    """Async job processing for long-running operations."""
    
    async def queue_welcome_email(self, user_id: int) -> str:
        """Queue email sending as background job."""
        # Add job to queue
        # Return job ID for tracking
        # Process asynchronously
        pass
```

We'll explore how to build applications that scale horizontally while maintaining the clean architecture and comprehensive observability you've established.
