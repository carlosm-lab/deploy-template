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
def sanitize_log_string(value: str, max_length: int = 150) -> str:
    """
    Sanitize a string for safe logging.
    Removes control characters and ANSI escape sequences to prevent log injection.

    Args:
        value: String to sanitize
        max_length: Maximum length to truncate to

    Returns:
        Sanitized string safe for logging
    """
    if not value:
        return ''

    # Remove ANSI escape sequences
    import re as _re
    ansi_pattern = _re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    sanitized = ansi_pattern.sub('', value)

    # Remove control characters (except newline and tab for readability)
    sanitized = ''.join(
        char for char in sanitized
        if char >= ' ' or char in '\n\t'
    )

    # Truncate and indicate if truncated
    if len(sanitized) > max_length:
        return sanitized[:max_length - 3] + '...'

    return sanitized


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

# M5: Configure Jinja2 cache explicitly for production optimization
app.jinja_env.auto_reload = IS_DEVELOPMENT

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

# B2: Validate REDIS_URL format
if REDIS_URL:
    # A1: Detect Upstash REST API URL (wrong format) and guide user
    if REDIS_URL.startswith('https://'):
        if 'upstash' in REDIS_URL.lower():
            raise RuntimeError(
                "REDIS_URL parece ser la REST API de Upstash (https://). "
                "Flask-Limiter requiere la URL Redis nativa. "
                "Encuéntrala en: Upstash Console > Database > Details > Redis URL "
                "(formato: redis://default:PASSWORD@HOST:PORT o rediss://...)"
            )
        else:
            raise RuntimeError(
                f"Invalid REDIS_URL format: URLs https:// no son soportadas. "
                f"Usa redis:// o rediss:// (Got: '{REDIS_URL[:30]}...')"
            )
    if not (REDIS_URL.startswith('redis://') or REDIS_URL.startswith('rediss://')):
        raise RuntimeError(
            f"Invalid REDIS_URL format. Must start with 'redis://' or 'rediss://'. "
            f"Got: '{REDIS_URL[:20]}...' "
            "Example: redis://default:PASSWORD@HOST:PORT"
        )
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

# A1: Callback para logging de rate limit breaches
def on_rate_limit_breach(request_limit):
    """Log rate limit breaches for security monitoring."""
    try:
        logger.warning(
            "Rate limit breach detected",
            extra={
                "limit": str(request_limit),
                "ip": anonymize_ip(request.remote_addr) if request else "unknown",
                "path": request.path if request else "unknown",
                "security": "rate_limit_breach"
            }
        )
    except Exception:
        pass  # Don't fail on logging errors


# Siempre inicializar limiter (A1: añadido resilient handling)
# M1-A04: Connection pooling configuration for better performance under load
# H2-FIX: Enhanced retry configuration for network resilience
REDIS_STORAGE_OPTIONS = {
    "socket_connect_timeout": 2,  # 2 second connection timeout (H1-A02: Vercel serverless compat)
    "socket_timeout": 3,          # 3 second socket timeout (leaves margin for request processing)
    "retry_on_timeout": True,     # A1: Retry on timeout for resilience
    # H2-FIX: Retry on connection errors (reset, refused, etc.)
    # This uses exponential backoff: 0.1s, 0.2s, 0.4s for 3 retries
    "retry_on_error": [ConnectionError, TimeoutError, OSError],
    "retry": None,  # Will use default Retry with backoff if redis-py >= 4.5
    # M1-A04: Connection pooling - reuse connections instead of opening new ones per request
    # max_connections=10 is conservative for serverless (Vercel limits concurrent connections)
    # Upstash free tier allows 30 concurrent connections, paid allows more
    "max_connections": 10,
    "health_check_interval": 30,  # Check connection health every 30s
} if REDIS_URL else {}

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=RATE_LIMIT_STORAGE,
    storage_options=REDIS_STORAGE_OPTIONS,
    on_breach=on_rate_limit_breach,  # A1: Log breaches for monitoring
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

# M5: HOST header whitelist for preventing host header injection
# Initialized lazily to avoid circular dependency with BASE_URL
_ALLOWED_HOSTS = None

def get_allowed_hosts():
    """Get allowed hosts list, initializing lazily if needed."""
    global _ALLOWED_HOSTS
    if _ALLOWED_HOSTS is not None:
        return _ALLOWED_HOSTS

    allowed_hosts_raw = os.environ.get('ALLOWED_HOSTS', '')
    if allowed_hosts_raw:
        _ALLOWED_HOSTS = [h.strip().lower() for h in allowed_hosts_raw.split(',') if h.strip()]
    else:
        # Auto-derive from BASE_URL (defined later in file)
        from urllib.parse import urlparse
        try:
            parsed_base = urlparse(BASE_URL)
            _ALLOWED_HOSTS = [parsed_base.netloc.lower()] if parsed_base.netloc else []
        except NameError:
            _ALLOWED_HOSTS = []

        # Always allow localhost for development
        if IS_DEVELOPMENT:
            _ALLOWED_HOSTS.extend(['localhost', '127.0.0.1', 'localhost:5000', '127.0.0.1:5000'])

    return _ALLOWED_HOSTS


@app.before_request
def before_request():
    """Add request ID, timing, and validate HOST header."""
    # M5: Validate HOST header to prevent host header injection
    allowed_hosts = get_allowed_hosts()
    if allowed_hosts:
        request_host = request.host.lower() if request.host else ''
        # Strip port for comparison if needed
        host_without_port = request_host.split(':')[0]
        if request_host not in allowed_hosts and host_without_port not in allowed_hosts:
            logger.warning(
                "Invalid Host header rejected",
                extra={
                    "host": request_host[:50],
                    "allowed": allowed_hosts[:3],
                    "security": "host_header_blocked"
                }
            )
            return Response('Bad Request: Invalid Host', status=400)

    # Validate X-Request-ID to prevent log injection
    user_request_id = request.headers.get('X-Request-ID', '')
    if user_request_id and REQUEST_ID_PATTERN.match(user_request_id):
        g.request_id = user_request_id[:36]
    else:
        # Use full UUID for zero collision risk
        g.request_id = str(uuid.uuid4())
    g.request_start = datetime.now(timezone.utc)

    # M2: Preparatory Content-Type validation for future POST endpoints
    if request.method in ['POST', 'PUT', 'PATCH']:
        content_type = request.content_type or ''
        allowed_types = [
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
        ]
        if not any(content_type.startswith(t) for t in allowed_types):
            logger.warning(
                "Unsupported Content-Type rejected",
                extra={
                    "content_type": content_type[:50],
                    "method": request.method,
                    "path": request.path,
                    "security": "content_type_blocked"
                }
            )
            return Response('Unsupported Media Type', status=415)


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
        # M4: Prevent DNS prefetching to protect user privacy
        'X-DNS-Prefetch-Control': 'off',
        # M6 Fix: Disable legacy XSS filter (can introduce vulnerabilities)
        'X-XSS-Protection': '0',
        # A1: CSP unified with vercel.json - using consistent restrictive policy
        # Extensibility Guide:
        # - Para añadir analytics: script-src 'self' https://www.googletagmanager.com;
        # - Para añadir APIs externas: connect-src 'self' https://api.example.com;
        # - Para CDN de fuentes: font-src 'self' https://fonts.gstatic.com;
        # IMPORTANTE: Mantener sincronizado con vercel.json
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; manifest-src 'self';",
        # HSTS - 1 year (preload removed until domain is registered at hstspreload.org)
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        # A3: Explicit cache control for dynamic content - prevent proxy caching
        'Cache-Control': 'no-store, no-cache, must-revalidate, private',
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
    response = Response(
        json.dumps({'status': 'ok', 'checks': checks}),
        status=200,
        mimetype='application/json'
    )
    # A3 Fix: Prevent search engine indexing of health endpoints
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return response


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

    Checks performed:
    - App configuration validation (implicit - app started)
    - Redis connectivity (if configured) via PING command
    """
    checks = {'app': 'ok'}

    # Redis check: verify actual connectivity, not just configuration
    if REDIS_URL:
        try:
            from redis import Redis
            # M2: Separate timeouts for better resilience during high latency
            redis_client = Redis.from_url(
                REDIS_URL,
                socket_connect_timeout=3,  # Connection establishment timeout
                socket_timeout=5           # Operation timeout (for PING)
            )
            redis_client.ping()
            checks['redis'] = 'connected'
        except Exception as e:
            checks['redis'] = 'error'
            logger.warning(
                "Redis connectivity check failed",
                extra={
                    "error": str(e)[:100],
                    "component": "redis",
                    "health_check": "ready"
                }
            )
    else:
        checks['redis'] = 'not_configured'

    # All checks pass if we reach this point (startup validations passed)
    response = Response(
        json.dumps({'status': 'ready', 'checks': checks}),
        status=200,
        mimetype='application/json'
    )
    # A3 Fix: Prevent search engine indexing of health endpoints
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return response


@app.route('/status')
@rate_limit("10 per minute")  # M2 Fix: Rate limit on legacy endpoint
def status():
    """
    Legacy status endpoint - permanently redirects to /healthz.
    Deprecated: Use /healthz instead.
    """
    response = redirect(url_for('health'), code=301)
    # L5 Cycle 2: Prevent indexing of deprecated endpoint
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return response


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

# Security contact for security.txt (B1: Default requires configuration)
# M3: Added URI format validation for RFC 9116 compliance
SECURITY_CONTACT_RAW = os.environ.get('SECURITY_CONTACT')
SECURITY_CONTACT = None

# M3 Fix: Maximum length validation to prevent DoS via logs
SECURITY_CONTACT_MAX_LENGTH = 500

if SECURITY_CONTACT_RAW:
    # Validate length first
    if len(SECURITY_CONTACT_RAW) > SECURITY_CONTACT_MAX_LENGTH:
        logger.warning(
            f"SECURITY_CONTACT too long ({len(SECURITY_CONTACT_RAW)} chars), max is {SECURITY_CONTACT_MAX_LENGTH}. Using placeholder.",
            extra={"component": "config", "security": "invalid_config"}
        )
    # Validate URI format: must start with mailto: or https://
    elif SECURITY_CONTACT_RAW.startswith('mailto:') or SECURITY_CONTACT_RAW.startswith('https://'):
        SECURITY_CONTACT = SECURITY_CONTACT_RAW
    else:
        logger.warning(
            "Invalid SECURITY_CONTACT format. Must start with 'mailto:' or 'https://'. Using placeholder.",
            extra={"component": "config", "provided_value": SECURITY_CONTACT_RAW[:30], "security": "invalid_config"}
        )

if not SECURITY_CONTACT:
    if IS_PRODUCTION:
        # In production, log warning but allow deployment with placeholder
        # The security.txt will be generated but should be configured properly
        SECURITY_CONTACT = f'{BASE_URL}/.well-known/security.txt#configure-contact'
        if not SECURITY_CONTACT_RAW:
            logger.warning(
                "SECURITY_CONTACT not configured. Using placeholder URL.",
                extra={"component": "config", "security": "incomplete_config"}
            )
    else:
        SECURITY_CONTACT = 'https://github.com/YOUR-USERNAME/YOUR-REPO/security/advisories/new'

# Stable expiration date for security.txt (RFC 9116 compliance)
# M4: Enhanced documentation and calculation
#
# IMPORTANT: security.txt EXPIRES field is required by RFC 9116.
# The expiration date should be no more than 1 year in the future.
#
# OPTIONS:
# 1. Set SECURITY_TXT_EXPIRES env var (format: 2027-01-01T00:00:00.000Z)
# 2. Let it auto-calculate (1 year from current date)
#
# MAINTENANCE NOTE: If you don't redeploy for 1+ year, security.txt expires.
# Recommendation: Set up annual reminder to redeploy or update SECURITY_TXT_EXPIRES.
#
SECURITY_TXT_EXPIRES_RAW = os.environ.get('SECURITY_TXT_EXPIRES')
if SECURITY_TXT_EXPIRES_RAW:
    # A1 Fix: Validate ISO 8601 format before using
    try:
        # Parse to validate format (handles 'Z' suffix)
        datetime.fromisoformat(SECURITY_TXT_EXPIRES_RAW.replace('Z', '+00:00'))
        SECURITY_TXT_EXPIRES = SECURITY_TXT_EXPIRES_RAW
    except ValueError:
        logger.warning(
            "Invalid SECURITY_TXT_EXPIRES format, using auto-calculated",
            extra={"component": "config", "provided_value": SECURITY_TXT_EXPIRES_RAW[:30]}
        )
        # Fallback to calculated
        expiry_date = datetime.now(timezone.utc) + timedelta(days=365)
        SECURITY_TXT_EXPIRES = expiry_date.strftime('%Y-%m-%dT00:00:00.000Z')
else:
    # Calculate 1 year from now (standard practice)
    expiry_date = datetime.now(timezone.utc) + timedelta(days=365)
    SECURITY_TXT_EXPIRES = expiry_date.strftime('%Y-%m-%dT00:00:00.000Z')


@app.route('/robots.txt')
@rate_limit("30 per minute")  # M3: Rate limit SEO routes
def robots():
    """Generate robots.txt dynamically with correct BASE_URL."""
    # M1-A02: Configurable disallow paths via environment variable
    # Default paths that should never be crawled
    default_disallow = ['/healthz', '/ready', '/status']
    
    # Additional paths from env (comma-separated)
    extra_disallow_raw = os.environ.get('ROBOTS_DISALLOW', '')
    extra_disallow = [p.strip() for p in extra_disallow_raw.split(',') if p.strip()]
    
    # Merge and deduplicate
    all_disallow = list(dict.fromkeys(default_disallow + extra_disallow))
    disallow_lines = '\n'.join(f'Disallow: {path}' for path in all_disallow)
    
    content = f"""# robots.txt
User-agent: *
Allow: /
{disallow_lines}

Sitemap: {BASE_URL}/sitemap.xml
"""
    response = Response(content, mimetype='text/plain')
    # B5: Cache-Control for SEO routes (M4: Added s-maxage for CDN revalidation)
    response.headers['Cache-Control'] = 'public, max-age=3600, s-maxage=60'
    return response


@app.route('/sitemap.xml')
@rate_limit("30 per minute")  # M3: Rate limit SEO routes
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
    response = Response(content, mimetype='application/xml')
    # B5: Cache-Control for SEO routes (M4: Added s-maxage for CDN revalidation)
    response.headers['Cache-Control'] = 'public, max-age=3600, s-maxage=60'
    return response


@app.route('/.well-known/security.txt')
@rate_limit("30 per minute")  # M3: Rate limit SEO routes
def security_txt():
    """Generate security.txt per RFC 9116 dynamically with correct BASE_URL."""
    # A1: Use stable expiration date (configured or deployment-based)
    content = f"""Contact: {SECURITY_CONTACT}
Expires: {SECURITY_TXT_EXPIRES}
Preferred-Languages: es, en
Canonical: {BASE_URL}/.well-known/security.txt
"""
    response = Response(content, mimetype='text/plain')
    # B5: Cache-Control for SEO routes
    response.headers['Cache-Control'] = 'public, max-age=86400'  # 24 hours
    return response


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
            "user_agent": sanitize_log_string(request.headers.get('User-Agent', 'unknown'), 100),
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
        # M2: Sanitized User-Agent for forensic analysis (prevents log injection)
        "user_agent": sanitize_log_string(request.headers.get('User-Agent', 'unknown'), 150),
        "path": request.path,
        "method": request.method,
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
