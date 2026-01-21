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
from datetime import datetime, timezone, timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, g, Response, redirect, url_for, send_from_directory

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
# Deployment identification for logs (M4: observability)
DEPLOYMENT_ID = os.environ.get('VERCEL_DEPLOYMENT_ID', os.environ.get('VERCEL_GIT_COMMIT_SHA', 'local')[:12])


class JSONFormatter(logging.Formatter):
    """Formatter that outputs JSON for structured logging."""
    
    def format(self, record):
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "deployment_id": DEPLOYMENT_ID,
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
        # Development: Generate truly random key each startup
        # Sessions will reset on restart, but that's acceptable for dev
        SECRET_KEY = secrets.token_hex(32)
        # Note: Log happens at request time, not import time (Vercel compatibility)


# =============================================================================
# Application Factory
# =============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['WTF_CSRF_ENABLED'] = True  # Prepared for future forms

# Security: Limit request body size to prevent DoS (M4)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB

# Security: Cookie configuration (M5)
app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# =============================================================================
# Rate Limiting Configuration
# =============================================================================
# Siempre habilitado. Usa Redis si está disponible, memoria como fallback.
# En serverless sin Redis, el límite es por invocación (limitado pero funcional).
# =============================================================================

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Determinar storage backend (logs removed for Vercel compatibility)
REDIS_URL = os.environ.get('REDIS_URL') or os.environ.get('UPSTASH_REDIS_REST_URL')

if REDIS_URL:
    RATE_LIMIT_STORAGE = REDIS_URL
    # Logging happens at request time, not import time
elif IS_PRODUCTION:
    # CRITICAL: Production without Redis must fail explicitly
    raise RuntimeError(
        "REDIS_URL environment variable is required for rate limiting in production. "
        "Configure Upstash Redis (free tier available): https://upstash.com/ "
        "Or set SKIP_RATE_LIMIT=true if using Vercel Firewall (not recommended)."
    )
else:
    # Development: Local memory
    RATE_LIMIT_STORAGE = "memory://"

# Siempre inicializar limiter (A1: añadido storage_options con timeouts)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=RATE_LIMIT_STORAGE,
    storage_options={
        "socket_connect_timeout": 2,  # 2 second connection timeout
        "socket_timeout": 2,          # 2 second socket timeout
    } if REDIS_URL else {},
)

def rate_limit(limit_string):
    """Apply rate limit decorator."""
    return limiter.limit(limit_string)


# =============================================================================
# Context Processors
# =============================================================================
# Validate SITE_NAME to prevent malformed values (M5: added validation)
SITE_NAME_RAW = os.environ.get('SITE_NAME', 'VercelDeploy')
# Allow only alphanumeric, spaces, hyphens, and basic punctuation
SITE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\s\-_\.]+$')
if not SITE_NAME_PATTERN.match(SITE_NAME_RAW) or len(SITE_NAME_RAW) > 50:
    SITE_NAME = 'VercelDeploy'
    if IS_DEVELOPMENT:
        logger.warning(
            f"Invalid SITE_NAME '{SITE_NAME_RAW}' ignored, using default",
            extra={"component": "config", "provided_value": SITE_NAME_RAW[:20]}
        )
else:
    SITE_NAME = SITE_NAME_RAW


@app.context_processor
def inject_globals():
    """Inject global variables into all templates."""
    return {
        'current_year': datetime.now(timezone.utc).year,
        'site_name': SITE_NAME,
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
    
    # Remove server header to prevent fingerprinting
    response.headers.pop('Server', None)
    
    # Security headers for dev/prod parity (Vercel adds these too, but this ensures local dev matches)
    # Only add if not already present (allows Vercel to override)
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
        # CSP - Extensibility Guide:
        # - Para añadir analytics: script-src 'self' https://www.googletagmanager.com;
        # - Para añadir APIs externas: connect-src 'self' https://api.example.com;
        # - Para CDN de fuentes: font-src 'self' https://fonts.gstatic.com;
        # IMPORTANTE: Actualizar también vercel.json para consistencia
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; manifest-src 'self';",
        # HSTS - 1 year (preload removed until domain is registered at hstspreload.org)
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
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
# Token requerido en producción para proteger endpoint de monitoreo
HEALTH_CHECK_TOKEN = os.environ.get('HEALTH_CHECK_TOKEN')

if IS_PRODUCTION and not HEALTH_CHECK_TOKEN:
    # CRÍTICO: Token requerido en producción
    raise RuntimeError(
        "HEALTH_CHECK_TOKEN environment variable is required in production. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(16))\""
    )

def require_health_token(f):
    """Decorator to protect health endpoints with token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if HEALTH_CHECK_TOKEN:
            provided_token = request.headers.get('X-Health-Token', '')
            if not hmac.compare_digest(provided_token, HEALTH_CHECK_TOKEN):
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
    
    Returns status and basic checks.
    """
    checks = {
        'app': 'ok',
        'redis': 'configured' if REDIS_URL else 'not_configured'
    }
    return {'status': 'ok', 'checks': checks}, 200


@app.route('/ready')
@rate_limit("10 per minute")
@require_health_token
def ready():
    """
    Readiness check endpoint - verifies system can serve traffic.
    Protected by optional HEALTH_CHECK_TOKEN environment variable.
    
    Unlike /healthz (liveness), this indicates whether the app
    is configured and ready to handle requests properly.
    Useful for load balancers and orchestrators.
    
    Note: For this template, readiness means configuration is valid.
    In a full application, this would verify database connections, etc.
    """
    checks = {'app': 'ok'}
    
    # Redis check: reports configuration status
    # In production, REDIS_URL is required so this will be 'configured'
    checks['redis'] = 'configured' if REDIS_URL else 'not_configured'
    
    # All checks pass if we reach this point (startup validations passed)
    return {'status': 'ready', 'checks': checks}, 200


@app.route('/status')
def status():
    """
    Legacy status endpoint - permanently redirects to /healthz.
    Deprecated: Use /healthz instead.
    """
    return redirect(url_for('health'), code=301)


# =============================================================================
# SEO & Security Standard Routes (Dynamic Generation)
# =============================================================================
# Estas rutas generan contenido dinámicamente basado en BASE_URL para evitar
# URLs hardcodeadas. En producción, usar variable de entorno BASE_URL.
# =============================================================================

# Base URL configuration - required for SEO files (A2: Enhanced validation)
BASE_URL_RAW = os.environ.get('BASE_URL', 'http://localhost:5000')
# Remove trailing slash if present
BASE_URL_RAW = BASE_URL_RAW.rstrip('/')

# Validate BASE_URL format and enforce HTTPS in production (A2)
BASE_URL_PATTERN = re.compile(r'^https?://[a-zA-Z0-9][a-zA-Z0-9\-_.]+[a-zA-Z0-9](:[0-9]+)?(/.*)?$')
if not BASE_URL_PATTERN.match(BASE_URL_RAW):
    if IS_PRODUCTION:
        raise RuntimeError(
            f"Invalid BASE_URL format: '{BASE_URL_RAW}'. "
            "Must be a valid URL (e.g., https://example.vercel.app)"
        )
    BASE_URL = 'http://localhost:5000'
    logger.warning(
        f"Invalid BASE_URL '{BASE_URL_RAW}' ignored, using default",
        extra={"component": "config", "provided_value": BASE_URL_RAW[:50]}
    )
elif IS_PRODUCTION and BASE_URL_RAW.startswith('http://'):
    raise RuntimeError(
        f"BASE_URL must use HTTPS in production. Got: '{BASE_URL_RAW}'. "
        "Change to https:// for security."
    )
elif IS_PRODUCTION and BASE_URL_RAW == 'http://localhost:5000':
    raise RuntimeError(
        "BASE_URL not configured for production! "
        "Set BASE_URL environment variable (e.g., https://your-app.vercel.app)"
    )
else:
    BASE_URL = BASE_URL_RAW

# Security contact for security.txt
SECURITY_CONTACT = os.environ.get(
    'SECURITY_CONTACT', 
    'https://github.com/Memory-Bank/deploy/security/advisories/new'
)

# Stable expiration date for security.txt (A1: RFC 9116 compliance)
# Use deployment date or current date, expires in 1 year
# In production, use deployment timestamp for stability
if IS_PRODUCTION:
    # Use a stable date based on deployment (or fallback to configured date)
    SECURITY_TXT_EXPIRES = os.environ.get(
        'SECURITY_TXT_EXPIRES',
        (datetime.now(timezone.utc).replace(month=1, day=1) + timedelta(days=365+365)).strftime('%Y-%m-%dT00:00:00.000Z')
    )
else:
    # Development: use 1 year from now
    SECURITY_TXT_EXPIRES = (datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%dT00:00:00.000Z')


@app.route('/robots.txt')
def robots():
    """Generate robots.txt dynamically with correct BASE_URL."""
    content = f"""# robots.txt
User-agent: *
Allow: /

Sitemap: {BASE_URL}/sitemap.xml
"""
    return Response(content, mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap():
    """Generate sitemap.xml dynamically with correct BASE_URL."""
    # Get current date for lastmod
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    content = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>{BASE_URL}/</loc>
        <lastmod>{today}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>1.0</priority>
    </url>
</urlset>
"""
    return Response(content, mimetype='application/xml')


@app.route('/.well-known/security.txt')
def security_txt():
    """Generate security.txt per RFC 9116 dynamically with correct BASE_URL."""
    # A1: Use stable expiration date (configured or deployment-based)
    content = f"""Contact: {SECURITY_CONTACT}
Expires: {SECURITY_TXT_EXPIRES}
Preferred-Languages: es, en
Canonical: {BASE_URL}/.well-known/security.txt
"""
    return Response(content, mimetype='text/plain')


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
    """Rate limit exceeded handler with Retry-After header (A3: RFC 6585)."""
    # Enhanced logging for forensic analysis (M3: improved observability)
    retry_after_seconds = 60
    logger.warning(
        "Rate limit exceeded",
        extra={
            "path": request.path,
            "method": request.method,
            "ip": anonymize_ip(request.remote_addr),
            "error_type": "rate_limit",
            "user_agent": request.headers.get('User-Agent', 'unknown')[:100],
            "retry_after": retry_after_seconds,
            "limit_type": str(error.description) if hasattr(error, 'description') else 'unknown',
        }
    )
    response = app.make_response(render_template('errors/429.html'))
    response.status_code = 429
    # A3: Add Retry-After header (RFC 6585 compliance)
    response.headers['Retry-After'] = str(retry_after_seconds)
    return response


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
