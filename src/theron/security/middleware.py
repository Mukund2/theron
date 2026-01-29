"""Security middleware for Theron proxy and dashboard.

Implements:
- HTTP security headers
- Rate limiting
- Request size limits
- CORS restrictions
- Content-Type validation
"""

import time
from collections import defaultdict
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


# Security headers to add to all responses
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

# Content Security Policy for dashboard
DASHBOARD_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws://localhost:* wss://localhost:*; "
    "font-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

# Allowed origins for CORS (localhost only)
ALLOWED_ORIGINS = [
    "http://localhost:8080",
    "http://localhost:8081",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8081",
]


class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, requests_per_minute: int = 100):
        self.requests_per_minute = requests_per_minute
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        """Check if request is allowed for this client."""
        now = time.time()
        minute_ago = now - 60

        # Clean old entries
        self.requests[client_ip] = [
            t for t in self.requests[client_ip] if t > minute_ago
        ]

        # Check limit
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return False

        # Record request
        self.requests[client_ip].append(now)
        return True

    def get_remaining(self, client_ip: str) -> int:
        """Get remaining requests for this client."""
        now = time.time()
        minute_ago = now - 60
        recent = [t for t in self.requests[client_ip] if t > minute_ago]
        return max(0, self.requests_per_minute - len(recent))


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""

    def __init__(self, app, include_csp: bool = False):
        super().__init__(app)
        self.include_csp = include_csp

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Add security headers
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value

        # Add CSP for dashboard
        if self.include_csp:
            response.headers["Content-Security-Policy"] = DASHBOARD_CSP

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware for rate limiting requests."""

    def __init__(self, app, requests_per_minute: int = 100):
        super().__init__(app)
        self.limiter = RateLimiter(requests_per_minute)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Check rate limit
        if not self.limiter.is_allowed(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.limiter.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)

        # Add rate limit headers
        remaining = self.limiter.get_remaining(client_ip)
        response.headers["X-RateLimit-Limit"] = str(self.limiter.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to limit request body size."""

    def __init__(self, app, max_size_bytes: int = 10 * 1024 * 1024):  # 10MB default
        super().__init__(app)
        self.max_size_bytes = max_size_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check Content-Length header
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > self.max_size_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "Request too large",
                            "message": f"Request body exceeds maximum size of {self.max_size_bytes} bytes",
                        },
                    )
            except ValueError:
                pass  # Invalid content-length, let it through for other validation

        return await call_next(request)


class ContentTypeValidationMiddleware(BaseHTTPMiddleware):
    """Middleware to validate Content-Type for POST/PUT requests."""

    REQUIRED_CONTENT_TYPES = ["application/json"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only check POST/PUT requests
        if request.method in ("POST", "PUT"):
            content_type = request.headers.get("content-type", "")

            # Skip for health checks and static files
            if request.url.path in ("/health", "/"):
                return await call_next(request)

            # Check content type
            if not any(ct in content_type for ct in self.REQUIRED_CONTENT_TYPES):
                # Allow empty body for some endpoints
                content_length = request.headers.get("content-length", "0")
                if content_length != "0":
                    return JSONResponse(
                        status_code=415,
                        content={
                            "error": "Unsupported Media Type",
                            "message": "Content-Type must be application/json",
                        },
                    )

        return await call_next(request)


class HostValidationMiddleware(BaseHTTPMiddleware):
    """Middleware to validate Host header (prevent DNS rebinding)."""

    ALLOWED_HOSTS = [
        "localhost",
        "127.0.0.1",
        "localhost:8080",
        "localhost:8081",
        "127.0.0.1:8080",
        "127.0.0.1:8081",
    ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        host = request.headers.get("host", "")

        # Validate host
        if host and not any(h in host for h in ["localhost", "127.0.0.1"]):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Invalid Host",
                    "message": "Theron only accepts requests to localhost",
                },
            )

        return await call_next(request)


def add_security_middleware(
    app: FastAPI,
    include_csp: bool = False,
    rate_limit: int = 100,
    max_request_size: int = 10 * 1024 * 1024,
) -> None:
    """Add all security middleware to a FastAPI app.

    Args:
        app: FastAPI application
        include_csp: Whether to include Content-Security-Policy header
        rate_limit: Requests per minute limit
        max_request_size: Maximum request body size in bytes
    """
    # Add CORS middleware (must be added before other middleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        max_age=3600,
    )

    # Add security headers
    app.add_middleware(SecurityHeadersMiddleware, include_csp=include_csp)

    # Add rate limiting
    app.add_middleware(RateLimitMiddleware, requests_per_minute=rate_limit)

    # Add request size limit
    app.add_middleware(RequestSizeLimitMiddleware, max_size_bytes=max_request_size)

    # Add content type validation
    app.add_middleware(ContentTypeValidationMiddleware)

    # Add host validation
    app.add_middleware(HostValidationMiddleware)
