"""
Flask Application - Under Construction Template
Plantilla profesional lista para producción en Vercel
"""

import os
import json
import re
import secrets
import traceback
import uuid
import logging
import ipaddress
import hmac
from datetime import datetime, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, g, Response, redirect, url_for

# Load environment variables from .env files (development)
load_dotenv()

# =============================================================================
# Environment Detection
# =============================================================================
IS_PRODUCTION = bool(os.environ.get('VERCEL'))
IS_DEVELOPMENT = not IS_PRODUCTION


# =============================================================================
# Structured JSON Logger
# =============================================================================
class JSONFormatter(logging.Formatter):
    """Formatter that outputs JSON for structured logging."""
    
    def format(self, record):
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Add request context if available
        try:
            if hasattr(g, 'request_id'):
                log_record["request_id"] = g.request_id
        except RuntimeError:
            # Outside of request context
            pass
        if hasattr(record, 'extra'):
            log_record.update(record.extra)
        return json.dumps(log_record)


# Configure logging with configurable level (M5: validated input)
LOG_LEVEL_RAW = os.environ.get('LOG_LEVEL', 'INFO').upper()
VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
if LOG_LEVEL_RAW not in VALID_LOG_LEVELS:
    LOG_LEVEL = 'INFO'
else:
    LOG_LEVEL = LOG_LEVEL_RAW

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=getattr(logging, LOG_LEVEL), handlers=[handler])
logger = logging.getLogger(__name__)

# Warn if invalid LOG_LEVEL was provided
if LOG_LEVEL_RAW not in VALID_LOG_LEVELS:
    logger.warning(
        f"Invalid LOG_LEVEL '{LOG_LEVEL_RAW}' ignored, using INFO",
        extra={"component": "config", "provided_value": LOG_LEVEL_RAW}
    )


# =============================================================================
# Privacy Utilities (GDPR Compliant)
# =============================================================================
def anonymize_ip(ip_address: str) -> str:
    """
    Anonimiza una dirección IP para cumplimiento GDPR.
    Usa el módulo ipaddress para manejo robusto de todos los formatos.
    
    Política de Anonimización:
    - IPv4: Reemplaza último octeto con 0 (/24 - ~256 hosts)
    - IPv6: Mantiene solo /48 (~65K subnets)
    
    Nota de Compliance:
    Esta anonimización cumple con la mayoría de interpretaciones de GDPR.
    Para requerimientos más estrictos, considerar no logear IPs en absoluto.
    """
    if not ip_address:
        return 'unknown'
    
    try:
        # Handle IPv4-mapped IPv6 addresses (::ffff:192.168.1.1)
        addr = ipaddress.ip_address(ip_address)
        
        if isinstance(addr, ipaddress.IPv4Address):
            # Zero out last octet: 192.168.1.100 -> 192.168.1.0
            network = ipaddress.IPv4Network(f"{ip_address}/24", strict=False)
            return str(network.network_address)
        
        elif isinstance(addr, ipaddress.IPv6Address):
            # Zero out last 80 bits (keep /48): 2001:db8:85a3::1 -> 2001:db8:85a3::
            network = ipaddress.IPv6Network(f"{ip_address}/48", strict=False)
            return str(network.network_address)
    
    except ValueError:
        # Invalid IP format
        return 'invalid-ip'
    
    return 'unknown'


# =============================================================================
# Security Configuration
# =============================================================================
SECRET_KEY = os.environ.get('SECRET_KEY')

if not SECRET_KEY:
    if IS_PRODUCTION:
        # CRITICAL: Fail explicitly in production - do not allow weak keys
        raise RuntimeError(
            "SECRET_KEY environment variable is required in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    else:
        # Development only: Generate deterministic key based on working directory
        # This prevents session invalidation on restart while keeping dev simple
        import hashlib
        dev_seed = os.path.abspath(os.getcwd()).encode()
        SECRET_KEY = hashlib.sha256(dev_seed + b'dev-only-key').hexdigest()
        logger.warning(
            "SECRET_KEY not configured. Using deterministic dev key (NOT for production).",
            extra={"security": "warning", "component": "config"}
        )


# =============================================================================
# Application Factory
# =============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['WTF_CSRF_ENABLED'] = True  # Prepared for future forms

# =============================================================================
# Rate Limiting Configuration
# =============================================================================
# NOTE: In Vercel serverless, memory-based rate limiting doesn't work because
# each function invocation has isolated memory. For production rate limiting,
# rely on Vercel Edge or use Redis (e.g., Upstash).
#
# This limiter is only effective for local development.
ENABLE_RATE_LIMIT = os.environ.get('ENABLE_RATE_LIMIT', 'false').lower() == 'true'

if ENABLE_RATE_LIMIT or IS_DEVELOPMENT:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
        enabled=ENABLE_RATE_LIMIT or IS_DEVELOPMENT,
    )
    
    def rate_limit(limit_string):
        """Apply rate limit decorator."""
        return limiter.limit(limit_string)
else:
    # No-op decorator for production
    # IMPORTANT: In production (Vercel), configure rate limiting via:
    # - Vercel Dashboard > Project Settings > Security > Rate Limiting
    # - Or use Vercel Firewall / WAF for enterprise
    def rate_limit(limit_string):
        def decorator(f):
            return f
        return decorator
    limiter = None
    
    logger.info(
        "Flask rate limiting disabled. Configure rate limiting in Vercel Dashboard for production.",
        extra={"component": "security", "production": True}
    )


# =============================================================================
# Context Processors
# =============================================================================
@app.context_processor
def inject_globals():
    """Inject global variables into all templates."""
    return {
        'current_year': datetime.now(timezone.utc).year
    }


# =============================================================================
# Request Middleware
# =============================================================================
# Regex for validating X-Request-ID format (alphanumeric, dashes, max 36 chars)
REQUEST_ID_PATTERN = re.compile(r'^[a-zA-Z0-9-]{1,36}$')


@app.before_request
def before_request():
    """Add request ID and timing for observability."""
    # Validate X-Request-ID to prevent log injection
    user_request_id = request.headers.get('X-Request-ID', '')
    if user_request_id and REQUEST_ID_PATTERN.match(user_request_id):
        g.request_id = user_request_id[:36]
    else:
        # Use full UUID for zero collision risk
        g.request_id = str(uuid.uuid4())
    g.request_start = datetime.now(timezone.utc)


@app.after_request
def after_request(response):
    """Add security headers and request correlation."""
    # Add request ID to response for tracing
    response.headers['X-Request-ID'] = g.request_id
    
    # Security headers for dev/prod parity (Vercel adds these too, but this ensures local dev matches)
    # Only add if not already present (allows Vercel to override)
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
        # CSP matches vercel.json for dev/prod parity
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; manifest-src 'self';",
        # HSTS - 1 year with preload
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    }
    for header, value in security_headers.items():
        if header not in response.headers:
            response.headers[header] = value
    
    # Log request completion
    duration_ms = (datetime.now(timezone.utc) - g.request_start).total_seconds() * 1000
    logger.info(
        f"{request.method} {request.path} {response.status_code}",
        extra={
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "duration_ms": round(duration_ms, 2),
            "ip": anonymize_ip(request.remote_addr),
        }
    )
    return response


# =============================================================================
# Health Check with Token Protection
# =============================================================================
def require_health_token(f):
    """Decorator to protect health endpoints with optional token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In production, require a secret token if configured
        health_token = os.environ.get('HEALTH_CHECK_TOKEN')
        if health_token:
            provided_token = request.headers.get('X-Health-Token', '')
            # Use hmac.compare_digest to prevent timing attacks
            if not hmac.compare_digest(provided_token, health_token):
                return Response('Unauthorized', status=401)
        return f(*args, **kwargs)
    return decorated_function


# =============================================================================
# Routes
# =============================================================================
@app.route('/')
def index():
    """Main page - Under construction."""
    return render_template('index.html')


@app.route('/healthz')
@rate_limit("10 per minute")
@require_health_token
def health():
    """
    Health check endpoint for monitoring.
    Protected by optional HEALTH_CHECK_TOKEN environment variable.
    
    Returns minimal information to prevent information disclosure.
    """
    return {'status': 'ok'}


@app.route('/status')
def status():
    """
    Legacy status endpoint - permanently redirects to /healthz.
    Deprecated: Use /healthz instead.
    """
    return redirect(url_for('health'), code=301)


# =============================================================================
# Development-Only Routes (A5: for testing error handlers)
# =============================================================================
if IS_DEVELOPMENT:
    @app.route('/test-error')
    def test_error():
        """
        Development-only endpoint to test 500 error handling.
        NOT available in production.
        """
        raise RuntimeError("Intentional test error for 500 handler verification")



# =============================================================================
# Error Handlers
# =============================================================================
@app.errorhandler(403)
def forbidden_error(error):
    """Custom 403 error page (M4: added missing handler)."""
    logger.warning(
        "Forbidden access attempt",
        extra={
            "path": request.path,
            "ip": anonymize_ip(request.remote_addr),
            "error_type": "forbidden"
        }
    )
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found_error(error):
    """Custom 404 error page."""
    logger.warning(
        "Page not found",
        extra={
            "path": request.path,
            "ip": anonymize_ip(request.remote_addr),
            "error_type": "not_found"
        }
    )
    return render_template('errors/404.html'), 404


@app.errorhandler(429)
def ratelimit_handler(error):
    """Rate limit exceeded handler."""
    logger.warning(
        "Rate limit exceeded",
        extra={
            "path": request.path,
            "ip": anonymize_ip(request.remote_addr),
            "error_type": "rate_limit"
        }
    )
    return {
        'error': 'rate_limit_exceeded',
        'message': 'Too many requests. Please try again later.'
    }, 429


@app.errorhandler(500)
def internal_error(error):
    """Custom 500 error page."""
    # Log with correlation ID for debugging
    error_id = g.get('request_id', 'unknown')
    
    # Build log extra data - sanitize in production
    log_extra = {
        "error_type": "internal",
        "error_id": error_id,
        "exception_type": type(error).__name__,
    }
    
    # Only include full traceback in development (security: prevent info disclosure)
    if IS_DEVELOPMENT:
        exc_info = traceback.format_exc()
        if exc_info != 'NoneType: None\n':
            log_extra["traceback"] = exc_info
            log_extra["exception"] = str(error)
    
    logger.error(f"Internal server error (ref: {error_id})", extra=log_extra)
    return render_template('errors/500.html', error_id=error_id), 500


# Note: We intentionally don't use @app.errorhandler(Exception) as it can
# catch SystemExit and KeyboardInterrupt. The 500 handler above handles
# HTTP 500 errors, and Flask's default exception handling is more appropriate
# for unexpected exceptions during development.


# =============================================================================
# Entry Point
# =============================================================================
if __name__ == '__main__':
    # SECURITY: Never allow debug mode in production, regardless of env var
    debug_requested = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    debug_mode = IS_DEVELOPMENT and debug_requested
    port = int(os.environ.get('PORT', 5000))
    
    # Log security warning if debug was requested in production
    if IS_PRODUCTION and debug_requested:
        logger.error(
            "FLASK_DEBUG=true IGNORED in production for security. Debug mode blocked.",
            extra={"security": "blocked", "component": "config"}
        )
    
    if debug_mode:
        logger.info("Starting in DEBUG mode (development only)", extra={"mode": "debug"})
        app.run(debug=True, host='127.0.0.1', port=port)
    else:
        logger.info("Starting in PRODUCTION mode", extra={"mode": "production"})
        app.run(debug=False, host='127.0.0.1', port=port)
