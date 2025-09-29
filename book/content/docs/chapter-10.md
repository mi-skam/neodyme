---
title: "Chapter 10"
weight: 10
type: docs
---
# Chapter 10: "I Need Deployment That Actually Works"

Your neodyme application is secure, well-tested, and properly configured. But now comes the moment of truth: getting it running reliably in production. You've probably deployed applications before, only to discover they work perfectly on your laptop but fail mysteriously in production.

*"It works on my machine" becomes "why does the container keep crashing?" Database connections fail, environment variables are missing, health checks timeout, and the application that passed all tests can't even start in production.*

This is the deployment reality that breaks so many applications: **code that works everywhere except where it needs to work most**. The question isn't whether deployment will be challenging—it's whether your deployment strategy will make problems visible and fixable, or hide them until they cause outages.

## The Problem: Deployment Surprises That Break Everything

Let me ask you: Have you ever spent hours debugging a deployment failure only to discover it was caused by a missing environment variable that worked fine in development? If so, you've experienced the pain of deployment surprises.

Here's what deployment typically looks like when it's not properly planned:

```python
# What seems like it should work but fails in production
# Local development script
export DATABASE_URL="sqlite:///./dev.db"
export SECRET_KEY="dev-secret-key"
export DEBUG="True"
python main.py  # Works perfectly!

# Production deployment script
export DATABASE_URL="postgresql://user:pass@prod-db/app"
export SECRET_KEY="prod-secret"  # Oops, too short!
export DEBUG="False"
python main.py  # Crashes with validation error!

# Docker attempt
FROM python:3.11
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "main.py"]
# Container builds but crashes at runtime with permission errors

# Production environment
server:~$ python main.py
ModuleNotFoundError: No module named 'neodyme'
# PYTHONPATH not set correctly

# Load balancer health check
curl http://app:8000/health
# Connection refused - app listening on localhost instead of 0.0.0.0

# Database connection
sqlalchemy.exc.OperationalError: could not connect to server
# Database credentials work locally but fail in production network
```

**Why this ad-hoc approach creates systematic deployment failures:**

- **Environment inconsistency** - Development environments differ from production in ways that aren't discovered until deployment
- **Dependency version drift** - Local development uses different package versions than production, causing unexpected behavior
- **Network configuration differences** - Applications that work with localhost fail when they need to accept connections from load balancers
- **Permission and security issues** - Containers running as root work locally but violate production security policies
- **Resource limitation surprises** - Applications that work with unlimited local resources fail when they hit production memory or CPU limits
- **Configuration validation gaps** - Configuration that's never validated until production deployment causes startup failures

The fundamental problem is **treating deployment as an afterthought**. Deployment isn't just running your code somewhere else—it's running your code in a completely different environment with different constraints, security requirements, and failure modes.

## Why "Just Run It in Docker" Isn't Enough

The naive approach to containerization looks like this:

```dockerfile
# Dockerfile that works locally but fails in production
FROM python:3.11

# Copy everything (including secrets, cache files, and dev dependencies)
COPY . /app
WORKDIR /app

# Install everything as root
RUN pip install -r requirements.txt

# Run as root (security vulnerability)
CMD ["python", "main.py"]
```

**This approach fails because:**

- **Security vulnerabilities** - Running containers as root violates security best practices and enables privilege escalation attacks
- **Image size bloat** - Including development files, cache directories, and unnecessary dependencies creates huge images that are slow to deploy
- **Secret exposure** - Copying the entire directory includes sensitive files like .env files with secrets
- **Build optimization absence** - No layer caching optimization means every code change requires rebuilding the entire environment
- **Health check missing** - Container orchestrators can't determine if the application is healthy and ready for traffic
- **Resource limits undefined** - Containers can consume unlimited resources, causing node failures in production
- **Signal handling broken** - Applications don't handle shutdown signals properly, causing data loss during deployments

## The Professional Deployment Solution: Production-Ready Containers

Professional deployment builds containers that work reliably in production environments. Here's how neodyme implements this:

```dockerfile
# Dockerfile - Multi-stage production build
# Stage 1: Build dependencies
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production runtime
FROM python:3.11-slim as production

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r appuser && \
    useradd -r -g appuser appuser && \
    mkdir -p /app && \
    chown appuser:appuser /app

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code (excluding development files)
COPY --chown=appuser:appuser neodyme/ neodyme/
COPY --chown=appuser:appuser alembic/ alembic/
COPY --chown=appuser:appuser alembic.ini .
COPY --chown=appuser:appuser pyproject.toml .
COPY --chown=appuser:appuser docker/ docker/

# Switch to non-root user
USER appuser

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Use custom entrypoint for proper startup sequence
ENTRYPOINT ["python", "docker/entrypoint.py"]
```

**Why this multi-stage approach creates reliable deployments:**

- **Security hardening** - Non-root user execution prevents privilege escalation and follows security best practices
- **Optimized image size** - Multi-stage build separates build dependencies from runtime, creating smaller production images
- **Layer caching optimization** - Dependencies are installed in separate layers, speeding up rebuilds when only application code changes
- **Health check integration** - Built-in health checks enable container orchestrators to manage application lifecycle properly
- **Signal handling** - Custom entrypoint ensures proper shutdown behavior during deployments
- **Resource awareness** - Environment variables and limits can be configured for different deployment environments

## Application Startup and Health Checks

Production applications need robust startup sequences and health monitoring:

```python
# docker/entrypoint.py - Production-ready startup sequence
#!/usr/bin/env python3
import os
import sys
import asyncio
import signal
import logging
from pathlib import Path
from typing import Optional

# Add application to Python path
sys.path.insert(0, "/app")

from neodyme.core.config import settings
from neodyme.core.startup import run_startup_checks
from neodyme.main import app

# Configure logging for container environment
logging.basicConfig(
    level=getattr(logging, settings.log_level.value),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

class GracefulShutdown:
    """Handle graceful shutdown for container environments."""
    
    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.server_task: Optional[asyncio.Task] = None
    
    def setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown."""
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_event.set()
    
    async def wait_for_shutdown(self):
        """Wait for shutdown signal."""
        await self.shutdown_event.wait()
    
    async def shutdown_server(self):
        """Shutdown server gracefully."""
        if self.server_task:
            logger.info("Shutting down server...")
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                logger.info("Server shutdown completed")

class HealthChecker:
    """Health check functionality for container orchestration."""
    
    @staticmethod
    async def check_application_health():
        """Comprehensive application health check."""
        try:
            # Check database connectivity
            from neodyme.core.database import engine
            from sqlalchemy import text
            
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            
            # Check configuration
            if not settings.secret_key:
                raise Exception("Secret key not configured")
            
            # Add more health checks as needed
            return True
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

async def main():
    """Main application startup sequence."""
    logger.info(f"Starting Neodyme API v{settings.app_version}")
    logger.info(f"Environment: {settings.environment.value}")
    logger.info(f"Python path: {sys.path}")
    
    # Set up graceful shutdown handling
    shutdown_handler = GracefulShutdown()
    shutdown_handler.setup_signal_handlers()
    
    try:
        # Run comprehensive startup validation
        logger.info("Running startup validation...")
        if not await run_startup_checks():
            logger.error("Startup validation failed - exiting")
            sys.exit(1)
        
        logger.info("Startup validation completed successfully")
        
        # Run database migrations if needed
        if settings.environment != "testing":
            logger.info("Checking database migrations...")
            await run_migrations()
        
        # Start the application server
        import uvicorn
        from uvicorn.config import Config
        from uvicorn.server import Server
        
        # Configure uvicorn for production
        config = Config(
            app=app,
            host="0.0.0.0",  # Listen on all interfaces
            port=int(os.getenv("PORT", "8000")),
            log_level=settings.log_level.value.lower(),
            access_log=settings.debug,
            reload=False,  # Never reload in production
            workers=1,  # Single worker for async apps
            loop="uvloop" if sys.platform != "win32" else "asyncio",
            lifespan="on"
        )
        
        server = Server(config)
        
        # Create server task
        shutdown_handler.server_task = asyncio.create_task(server.serve())
        
        logger.info(f"Server started on http://0.0.0.0:{config.port}")
        
        # Wait for shutdown signal
        await shutdown_handler.wait_for_shutdown()
        
        # Graceful shutdown
        await shutdown_handler.shutdown_server()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Application startup failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Application shutdown completed")

async def run_migrations():
    """Run database migrations during startup."""
    try:
        from alembic.config import Config
        from alembic import command
        
        # Configure alembic for container environment
        alembic_cfg = Config("/app/alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", str(settings.database_url))
        
        # Run migrations
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations completed successfully")
        
    except Exception as e:
        logger.error(f"Database migration failed: {e}")
        raise

if __name__ == "__main__":
    # Run the application
    asyncio.run(main())
```

**Why robust startup sequences prevent deployment failures:**

- **Startup validation** - Application validates all dependencies before accepting traffic, failing fast if configuration is invalid
- **Database migration integration** - Migrations run automatically during deployment, ensuring schema consistency
- **Graceful shutdown handling** - Proper signal handling prevents data loss during container restarts and deployments
- **Health check implementation** - Real health checks verify application readiness, not just process existence
- **Comprehensive logging** - Structured logging provides visibility into startup sequence and failure points

## Health Monitoring and Observability

Production applications need comprehensive health monitoring:

```python
# routes/health.py - Production health monitoring
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import asyncio
import psutil
import sys

from neodyme.core.config import settings
from neodyme.core.database import get_async_session
from neodyme.core.startup import startup_validator

router = APIRouter(tags=["health"])

class HealthMonitor:
    """Comprehensive health monitoring for production."""
    
    def __init__(self):
        self.start_time = datetime.utcnow()
        self.last_health_check = None
        self.health_history = []
    
    async def get_basic_health(self) -> Dict[str, Any]:
        """Basic health check for load balancer probes."""
        try:
            # Quick application health check
            uptime = datetime.utcnow() - self.start_time
            
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "uptime_seconds": int(uptime.total_seconds()),
                "version": settings.app_version,
                "environment": settings.environment.value
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_detailed_health(self) -> Dict[str, Any]:
        """Detailed health check for monitoring systems."""
        health_data = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {}
        }
        
        # Run all health checks
        checks = [
            ("database", self._check_database),
            ("memory", self._check_memory),
            ("disk", self._check_disk),
            ("external_services", self._check_external_services)
        ]
        
        overall_healthy = True
        
        for check_name, check_func in checks:
            try:
                check_result = await check_func()
                health_data["checks"][check_name] = check_result
                
                if check_result["status"] != "healthy":
                    overall_healthy = False
                    
            except Exception as e:
                health_data["checks"][check_name] = {
                    "status": "error",
                    "message": f"Health check failed: {e}",
                    "timestamp": datetime.utcnow().isoformat()
                }
                overall_healthy = False
        
        health_data["status"] = "healthy" if overall_healthy else "unhealthy"
        
        # Store health history
        self.last_health_check = health_data
        self.health_history.append({
            "timestamp": health_data["timestamp"],
            "status": health_data["status"]
        })
        
        # Keep only last 100 health checks
        if len(self.health_history) > 100:
            self.health_history = self.health_history[-100:]
        
        return health_data
    
    async def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity and performance."""
        try:
            from neodyme.core.database import engine
            from sqlalchemy import text
            import time
            
            start_time = time.time()
            
            async with engine.begin() as conn:
                # Test basic connectivity
                await conn.execute(text("SELECT 1"))
                
                # Test application tables
                await conn.execute(text("SELECT COUNT(*) FROM users LIMIT 1"))
            
            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "pool_size": engine.pool.size(),
                "checked_out_connections": engine.pool.checkedout(),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _check_memory(self) -> Dict[str, Any]:
        """Check memory usage."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            
            # Memory usage thresholds
            warning_threshold = 80.0  # 80%
            critical_threshold = 95.0  # 95%
            
            if memory_percent > critical_threshold:
                status = "critical"
            elif memory_percent > warning_threshold:
                status = "warning"
            else:
                status = "healthy"
            
            return {
                "status": status,
                "memory_usage_mb": round(memory_info.rss / 1024 / 1024, 2),
                "memory_usage_percent": round(memory_percent, 2),
                "virtual_memory_mb": round(memory_info.vms / 1024 / 1024, 2),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _check_disk(self) -> Dict[str, Any]:
        """Check disk usage."""
        try:
            disk_usage = psutil.disk_usage('/')
            
            # Disk usage thresholds
            warning_threshold = 80.0  # 80%
            critical_threshold = 95.0  # 95%
            
            usage_percent = (disk_usage.used / disk_usage.total) * 100
            
            if usage_percent > critical_threshold:
                status = "critical"
            elif usage_percent > warning_threshold:
                status = "warning"
            else:
                status = "healthy"
            
            return {
                "status": status,
                "disk_usage_percent": round(usage_percent, 2),
                "total_gb": round(disk_usage.total / 1024 / 1024 / 1024, 2),
                "used_gb": round(disk_usage.used / 1024 / 1024 / 1024, 2),
                "free_gb": round(disk_usage.free / 1024 / 1024 / 1024, 2),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _check_external_services(self) -> Dict[str, Any]:
        """Check external service dependencies."""
        services = {}
        overall_status = "healthy"
        
        # Check email service
        if settings.email_smtp_host:
            try:
                import smtplib
                import socket
                
                with smtplib.SMTP(settings.email_smtp_host, settings.email_smtp_port, timeout=5) as server:
                    server.noop()  # Simple connectivity test
                
                services["email"] = {
                    "status": "healthy",
                    "host": settings.email_smtp_host,
                    "port": settings.email_smtp_port
                }
                
            except Exception as e:
                services["email"] = {
                    "status": "unhealthy",
                    "error": str(e),
                    "host": settings.email_smtp_host
                }
                overall_status = "warning"
        
        # Check analytics service
        if settings.analytics_endpoint:
            try:
                import httpx
                
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(str(settings.analytics_endpoint))
                    if response.status_code < 500:
                        services["analytics"] = {
                            "status": "healthy",
                            "endpoint": str(settings.analytics_endpoint),
                            "response_code": response.status_code
                        }
                    else:
                        services["analytics"] = {
                            "status": "unhealthy",
                            "endpoint": str(settings.analytics_endpoint),
                            "response_code": response.status_code
                        }
                        overall_status = "warning"
                        
            except Exception as e:
                services["analytics"] = {
                    "status": "unhealthy",
                    "error": str(e),
                    "endpoint": str(settings.analytics_endpoint)
                }
                overall_status = "warning"
        
        return {
            "status": overall_status,
            "services": services,
            "timestamp": datetime.utcnow().isoformat()
        }

# Global health monitor
health_monitor = HealthMonitor()

@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Basic health check for load balancers."""
    health_data = await health_monitor.get_basic_health()
    
    if health_data["status"] == "healthy":
        return JSONResponse(content=health_data, status_code=200)
    else:
        return JSONResponse(content=health_data, status_code=503)

@router.get("/health/detailed", status_code=status.HTTP_200_OK)
async def detailed_health_check():
    """Detailed health check for monitoring systems."""
    health_data = await health_monitor.get_detailed_health()
    
    if health_data["status"] == "healthy":
        return JSONResponse(content=health_data, status_code=200)
    else:
        return JSONResponse(content=health_data, status_code=503)

@router.get("/health/ready", status_code=status.HTTP_200_OK)
async def readiness_check():
    """Readiness check for Kubernetes."""
    try:
        # Run startup validation to ensure app is ready
        if await startup_validator.validate_all():
            return {"status": "ready", "timestamp": datetime.utcnow().isoformat()}
        else:
            return JSONResponse(
                content={"status": "not_ready", "timestamp": datetime.utcnow().isoformat()},
                status_code=503
            )
    except Exception as e:
        return JSONResponse(
            content={"status": "error", "error": str(e), "timestamp": datetime.utcnow().isoformat()},
            status_code=503
        )

@router.get("/health/live", status_code=status.HTTP_200_OK)
async def liveness_check():
    """Liveness check for Kubernetes."""
    # Simple check that the application is running
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": int((datetime.utcnow() - health_monitor.start_time).total_seconds())
    }
```

**Why comprehensive health monitoring is essential:**

- **Load balancer integration** - Simple health checks enable load balancers to route traffic only to healthy instances
- **Container orchestration support** - Separate readiness and liveness checks support Kubernetes deployment patterns
- **Performance monitoring** - Detailed health checks provide metrics for capacity planning and performance optimization
- **Dependency visibility** - External service health checks help diagnose issues with third-party dependencies
- **Historical tracking** - Health history enables trend analysis and capacity planning

## Container Orchestration and Deployment

Production deployments need orchestration for reliability and scalability:

```yaml
# docker-compose.prod.yml - Production container orchestration
version: '3.8'

services:
  app:
    build:
      context: .
      target: production
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=${DATABASE_URL}
      - SECRET_KEY=${SECRET_KEY}
      - EMAIL_SMTP_HOST=${EMAIL_SMTP_HOST}
      - EMAIL_SMTP_PORT=${EMAIL_SMTP_PORT}
      - EMAIL_SMTP_USERNAME=${EMAIL_SMTP_USERNAME}
      - EMAIL_SMTP_PASSWORD=${EMAIL_SMTP_PASSWORD}
      - EMAIL_FROM_ADDRESS=${EMAIL_FROM_ADDRESS}
    depends_on:
      db:
        condition: service_healthy
    networks:
      - app-network
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  db:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    networks:
      - app-network
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - app-network
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.25'

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - app-network
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

networks:
  app-network:
    driver: bridge
```

```nginx
# nginx/nginx.conf - Production load balancer configuration
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';

    access_log /var/log/nginx/access.log main;

    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/css
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Upstream application servers
    upstream app_servers {
        least_conn;
        server app:8000 max_fails=3 fail_timeout=30s;
        keepalive 32;
    }

    # HTTP server (redirect to HTTPS)
    server {
        listen 80;
        server_name _;
        
        # Health check endpoint (don't redirect)
        location /health {
            proxy_pass http://app_servers;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
        
        # Redirect all other traffic to HTTPS
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name _;

        # SSL configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # API endpoints
        location /api {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://app_servers;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
            
            # Buffering
            proxy_buffering on;
            proxy_buffer_size 4k;
            proxy_buffers 8 4k;
        }

        # Login endpoint with stricter rate limiting
        location /api/v1/auth/login {
            limit_req zone=login burst=3 nodelay;
            
            proxy_pass http://app_servers;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health checks
        location /health {
            proxy_pass http://app_servers;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            access_log off;
        }

        # Static files (if any)
        location /static {
            root /var/www;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}
```

**Why proper container orchestration is critical:**

- **High availability** - Multiple application replicas ensure service continuity during instance failures
- **Load balancing** - Nginx distributes traffic across application instances for better performance
- **Resource management** - CPU and memory limits prevent resource exhaustion and noisy neighbor problems
- **Health monitoring** - Container health checks enable automatic restart of failed instances
- **Security hardening** - SSL termination, security headers, and rate limiting protect against common attacks

## Deployment Automation and CI/CD

Production deployments need automation to reduce human error:

```yaml
# .github/workflows/deploy.yml - CI/CD pipeline
name: Deploy to Production

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
        cache: 'pip'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
    
    - name: Run linting
      run: |
        black --check .
        isort --check-only .
        flake8 .
        mypy .
    
    - name: Run tests
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test
        SECRET_KEY: test-secret-key-32-characters-long
        EMAIL_SMTP_HOST: localhost
        EMAIL_SMTP_PORT: 1025
        EMAIL_SMTP_USERNAME: test
        EMAIL_SMTP_PASSWORD: test
        EMAIL_FROM_ADDRESS: test@example.com
      run: |
        pytest --cov=neodyme --cov-report=xml --cov-report=term-missing
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml

  security:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Run security scan
      uses: pypa/gh-action-pip-audit@v1.0.8
      with:
        inputs: requirements.txt
    
    - name: Run Bandit security scan
      run: |
        pip install bandit
        bandit -r neodyme/ -f json -o bandit-report.json
    
    - name: Upload security scan results
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: bandit-report.json

  build:
    needs: [test, security]
    runs-on: ubuntu-latest
    
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
          type=raw,value=latest,enable={{is_default_branch}}
    
    - name: Build and push Docker image
      id: build
      uses: docker/build-push-action@v5
      with:
        context: .
        target: production
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        platforms: linux/amd64,linux/arm64

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Deploy to production
      env:
        IMAGE_DIGEST: ${{ needs.build.outputs.image-digest }}
      run: |
        # Update deployment configuration with new image
        sed -i "s|IMAGE_PLACEHOLDER|${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${IMAGE_DIGEST}|g" deploy/production.yml
        
        # Deploy using your orchestration platform
        # This could be Docker Swarm, Kubernetes, or cloud services
        echo "Deploying image with digest: ${IMAGE_DIGEST}"
    
    - name: Run deployment health checks
      run: |
        # Wait for deployment to be ready
        sleep 60
        
        # Verify health endpoints
        curl -f https://api.neodyme.com/health || exit 1
        curl -f https://api.neodyme.com/health/ready || exit 1
        
        echo "Deployment health checks passed"
    
    - name: Notify deployment status
      if: always()
      run: |
        if [ "${{ job.status }}" == "success" ]; then
          echo "✅ Deployment successful"
        else
          echo "❌ Deployment failed"
        fi
```

**Why automated deployment pipelines prevent production issues:**

- **Testing integration** - All code changes are automatically tested before deployment, preventing broken code from reaching production
- **Security scanning** - Automated security scans catch vulnerabilities before they're deployed to production environments
- **Consistent builds** - Container images are built consistently across environments, eliminating "works on my machine" problems
- **Deployment validation** - Health checks verify that deployments are successful before marking them complete
- **Rollback capability** - Failed deployments can be automatically rolled back to previous working versions

## What You've Learned

By the end of this chapter, you understand:

✅ **Why ad-hoc deployment creates systematic failures** - and how production-ready containers eliminate environment inconsistencies  
✅ **Multi-stage Docker builds for production** - creating secure, optimized containers that work reliably in production environments  
✅ **Application startup and health monitoring** - implementing robust startup sequences and comprehensive health checks  
✅ **Container orchestration patterns** - using Docker Compose and load balancers for high availability and scalability  
✅ **CI/CD automation strategies** - building deployment pipelines that catch issues before they reach production  
✅ **Production monitoring and observability** - implementing health checks and monitoring that enable reliable operations  

More importantly, you've built a deployment system that gets your application to production safely and keeps it running reliably.

## Building Blocks for Next Chapters

This deployment foundation gives us:
- **HTTP handling** ← Chapter 1: FastAPI basics
- **Data persistence** ← Chapter 2: Database integration  
- **Input validation** ← Chapter 3: Request/response validation
- **Schema evolution** ← Chapter 4: Database migrations
- **Clean architecture** ← Chapter 5: Service layer organization
- **Error handling** ← Chapter 6: Professional error management
- **Security** ← Chapter 7: Authentication and authorization
- **Configuration** ← Chapter 8: Environment-aware configuration
- **Testing** ← Chapter 9: Comprehensive testing strategies
- **Deployment** ← You are here
- **Monitoring** ← Chapter 11: Production observability

## Exercises

1. **Add blue-green deployment** - Implement zero-downtime deployments using blue-green deployment patterns
2. **Create auto-scaling** - Configure horizontal pod autoscaling based on CPU and memory metrics
3. **Implement secrets management** - Integrate with HashiCorp Vault or cloud secret management services
4. **Add canary deployments** - Implement gradual rollouts with automatic rollback on error rate increases
5. **Create disaster recovery** - Build backup and recovery procedures for database and application state

## Resources for Deeper Learning

### Container Best Practices
- **Docker Best Practices**: Official Docker security and optimization guidelines - https://docs.docker.com/develop/dev-best-practices/
- **Container Security**: Hardening containers for production - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- **Multi-stage Builds**: Optimizing Docker images - https://docs.docker.com/build/building/multi-stage/

### Container Orchestration
- **Docker Compose Production**: Production deployment patterns - https://docs.docker.com/compose/production/
- **Kubernetes Deployment**: Enterprise container orchestration - https://kubernetes.io/docs/concepts/workloads/controllers/deployment/
- **Health Checks and Probes**: Container health monitoring - https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/

### CI/CD and Automation
- **GitHub Actions**: Comprehensive CI/CD automation - https://docs.github.com/en/actions
- **GitLab CI/CD**: Alternative CI/CD platform - https://docs.gitlab.com/ee/ci/
- **Deployment Strategies**: Blue-green, rolling, and canary deployments - https://martinfowler.com/bliki/BlueGreenDeployment.html

### Production Operations
- **Site Reliability Engineering**: Google's approach to production systems - https://sre.google/
- **Production Readiness**: Checklist for production deployments - https://gruntwork.io/devops-checklist/
- **Incident Response**: Handling production issues effectively - https://response.pagerduty.com/

### Why These Resources Matter
- **Container security**: Production containers need proper security hardening to prevent breaches and privilege escalation
- **Orchestration patterns**: Understanding orchestration concepts helps you design scalable, reliable deployment architectures
- **Automation practices**: CI/CD automation prevents human error and enables rapid, safe deployments
- **Production operations**: Learning from SRE practices helps you build systems that stay reliable under real-world conditions

**Pro Tip**: Start with Docker best practices to build secure, optimized containers, then focus on health check patterns that enable reliable orchestration.

## Next: Production Monitoring and Observability

You have applications that deploy reliably to production, but now you need to understand how they're performing and quickly diagnose issues when they occur. How do you monitor application performance? How do you track down the root cause of production issues? How do you ensure your applications remain healthy over time?

In Chapter 11, we'll explore monitoring and observability strategies that give you visibility into production systems.

```python
# Preview of Chapter 11
import structlog
from prometheus_client import Counter, Histogram, Gauge

# Structured logging
logger = structlog.get_logger()

# Application metrics
request_counter = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration')
active_users = Gauge('active_users_total', 'Number of active users')

@router.post("/users/")
async def create_user(user_data: UserCreate):
    # Track request metrics
    request_counter.labels(method="POST", endpoint="/users", status="201").inc()
    
    # Log structured data
    logger.info("User registration started", user_email=user_data.email)
    
    # Application logic...
    pass
```

We'll explore how to build observability that helps you understand system behavior and solve problems quickly when they occur.
