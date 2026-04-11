# -*- coding: utf-8 -*-
"""Общие настройки (пути, middleware, лимиты). Окружение — development / production."""
import os

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = os.environ.get("STONECRAB_SECRET_KEY", "change-me-in-production")
DEBUG = False

REQUEST_ID_TRUST_CLIENT = False
RESPONSE_REQUEST_ID_HEADER = True
CSP_USE_NONCE = False
CONTENT_SECURITY_POLICY = None
UPLOAD_FORBIDDEN_EXTENSIONS = ()

SESSION_COOKIE_NAME = "demo_sid"
CSRF_HEADER_NAME = "X-CSRF-Token"
AUTH_SESSION_KEY = "auth_user_id"
SESSION_COOKIE_SECURE = None
SESSION_COOKIE_SAMESITE = "Lax"

MEDIA_URL = "/media/"
MEDIA_DIR = os.path.join(PROJECT_DIR, "media")
STATIC_URL = "/static/"
STATIC_DIR = os.path.join(PROJECT_DIR, "static")
TEMPLATE_DIRS = os.path.join(PROJECT_DIR, "templates")

MAX_REQUEST_BODY_BYTES = 10_000_000
MAX_HTTP_HEADERS = 80
CORS_ORIGINS = []
API_PATH_PREFIXES = ("/api",)
HSTS_MAX_AGE = 31536000
HSTS_INCLUDE_SUBDOMAINS = False
SENSITIVE_CACHE_PATH_PREFIXES = ("/api", "/admin")
HEALTH_PATH = "/health"
OPENAPI_PATH = "/openapi.json"
API_VERSION_PREFIX = ""
RESPONSE_CACHE_TTL = 0
IDEMPOTENCY_TTL = 3600
BEFORE_REQUEST_HOOKS = []
AFTER_REQUEST_HOOKS = []

# Порядок: внешний слой первым (ближе к клиенту).
MIDDLEWARE = [
    "TrustedHostMiddleware",
    "RequestIdMiddleware",
    "RequestLimitsMiddleware",
    "RateLimitMiddleware",
    "CorsMiddleware",
    "ApiOriginMiddleware",
    "MetricsMiddleware",
    "SecurityMiddleware",
    "HstsMiddleware",
    "SensitiveCacheMiddleware",
    "AuthenticationMiddleware",
    "ApiVersionPrefixMiddleware",
    "SessionMiddleware",
    "CsrfMiddleware",
    "IdempotencyMiddleware",
    "ResponseCacheMiddleware",
    "LogMiddleware",
    "GzipMiddleware",
    "RequestHooksMiddleware",
    "MessageMiddleware",
    "StaticfilesMiddleware",
    "CleanHTMLMiddleware",
]
