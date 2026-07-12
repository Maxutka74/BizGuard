from pathlib import Path
import os
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = os.environ.get("DEBUG", "True") == "True"
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "bizguard-dev-secret-key-change-in-production"
    else:
        raise RuntimeError("DJANGO_SECRET_KEY is required when DEBUG=False.")
ALLOWED_HOSTS = [host.strip() for host in os.environ.get("ALLOWED_HOSTS", "*").split(",") if host.strip()]
if DEBUG and "*" not in ALLOWED_HOSTS:
    for dev_host in ["localhost", "127.0.0.1", "0.0.0.0", "backend"]:
        if dev_host not in ALLOWED_HOSTS:
            ALLOWED_HOSTS.append(dev_host)
if not DEBUG and "*" in ALLOWED_HOSTS:
    raise RuntimeError("ALLOWED_HOSTS must not contain '*' when DEBUG=False.")
API_DOCS_ENABLED = os.environ.get("API_DOCS_ENABLED", str(DEBUG)).lower() == "true"

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    # BizGuard apps
    "apps.accounts",
    "apps.gmail",
    "apps.analysis",
    "apps.emails",
    "apps.threats",
    "apps.dashboard",
    "apps.reputation",
    "apps.licenses",
    "apps.billing",
]
if API_DOCS_ENABLED:
    INSTALLED_APPS.insert(INSTALLED_APPS.index("rest_framework"), "drf_spectacular")

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "config.middleware.SecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required. BizGuard uses PostgreSQL only.")

DATABASES = {
    "default": dj_database_url.config(
        default=DATABASE_URL,
        conn_max_age=int(os.environ.get("DB_CONN_MAX_AGE", "600")),
        conn_health_checks=True,
    )
}

AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ── REST Framework ────────────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.licenses.authentication.LicenseAwareJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "google_auth_url": os.environ.get("THROTTLE_GOOGLE_AUTH_URL", "30/min"),
        "google_callback": os.environ.get("THROTTLE_GOOGLE_CALLBACK", "20/min"),
        "token_refresh": os.environ.get("THROTTLE_TOKEN_REFRESH", "30/min"),
        "license_validate": os.environ.get("THROTTLE_LICENSE_VALIDATE", "10/min"),
        "license_activate": os.environ.get("THROTTLE_LICENSE_ACTIVATE", "10/min"),
        "license_confirm": os.environ.get("THROTTLE_LICENSE_CONFIRM", "10/min"),
        "scan": os.environ.get("THROTTLE_SCAN", "10/min"),
        "billing_checkout": os.environ.get("THROTTLE_BILLING_CHECKOUT", "20/min"),
        "billing_complete": os.environ.get("THROTTLE_BILLING_COMPLETE", "20/min"),
    },
}
if API_DOCS_ENABLED:
    REST_FRAMEWORK["DEFAULT_SCHEMA_CLASS"] = "drf_spectacular.openapi.AutoSchema"

SPECTACULAR_SETTINGS = {
    'TITLE': 'Monvirex API',
    'DESCRIPTION': 'Trading simulation platform',
    'VERSION': '1.0.0',
}

from datetime import timedelta
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

# ── CORS ──────────────────────────────────────────────────────────────────
CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOWED_ORIGINS = os.environ.get(
    "CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:5174,http://localhost:3000"
).split(",")
CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = os.environ.get(
    "CSRF_TRUSTED_ORIGINS", "http://localhost:5173,http://localhost:5174,http://localhost:3000"
).split(",")

SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", str(not DEBUG)).lower() == "true"
SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", "31536000" if not DEBUG else "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get("SECURE_HSTS_INCLUDE_SUBDOMAINS", str(not DEBUG)).lower() == "true"
SECURE_HSTS_PRELOAD = os.environ.get("SECURE_HSTS_PRELOAD", str(not DEBUG)).lower() == "true"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", str(not DEBUG)).lower() == "true"
CSRF_COOKIE_SECURE = os.environ.get("CSRF_COOKIE_SECURE", str(not DEBUG)).lower() == "true"
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = False
JWT_COOKIE_SECURE = os.environ.get("JWT_COOKIE_SECURE", str(not DEBUG)).lower() == "true"
JWT_COOKIE_SAMESITE = os.environ.get("JWT_COOKIE_SAMESITE", "Lax")
JWT_ACCESS_COOKIE_NAME = os.environ.get("JWT_ACCESS_COOKIE_NAME", "bizguard_access")
JWT_REFRESH_COOKIE_NAME = os.environ.get("JWT_REFRESH_COOKIE_NAME", "bizguard_refresh")

# ── Google OAuth ──────────────────────────────────────────────────────────
GOOGLE_OAUTH_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "")
GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "")
GOOGLE_OAUTH_REDIRECT_URI = os.environ.get(
    "GOOGLE_OAUTH_REDIRECT_URI", "http://localhost:5173/auth/callback"
)
GOOGLE_PUBLIC_OAUTH_REDIRECT_URI = os.environ.get(
    "GOOGLE_PUBLIC_OAUTH_REDIRECT_URI", "http://localhost:8000/api/accounts/google/public-redirect"
)
# Aliases used by apps.gmail.services.oauth
GOOGLE_CLIENT_ID = GOOGLE_OAUTH_CLIENT_ID
GOOGLE_CLIENT_SECRET = GOOGLE_OAUTH_CLIENT_SECRET
GOOGLE_REDIRECT_URI = GOOGLE_OAUTH_REDIRECT_URI

# License keys
LICENSE_KEY_HASH_SECRET = os.environ.get("LICENSE_KEY_HASH_SECRET", SECRET_KEY)
LICENSE_GATE_TOKEN_MAX_AGE_SECONDS = int(os.environ.get("LICENSE_GATE_TOKEN_MAX_AGE_SECONDS", "600"))

# ── AI / Reputation APIs ──────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_DISABLE_ON_RATE_LIMIT_SECONDS = int(os.environ.get("VIRUSTOTAL_DISABLE_ON_RATE_LIMIT_SECONDS", "900"))

# ── Sessions (needed for OAuth state) ────────────────────────────────────
SESSION_ENGINE = "django.contrib.sessions.backends.db"

# Celery / Redis
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL)
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = int(os.environ.get("CELERY_TASK_TIME_LIMIT", "1800"))
CELERY_TASK_SOFT_TIME_LIMIT = int(os.environ.get("CELERY_TASK_SOFT_TIME_LIMIT", "1500"))
CELERY_TASK_ROUTES = {
    "gmail.process_ai_queue": {"queue": "ai"},
    "gmail.analyze_pending_email": {"queue": "ai"},
}
CELERY_BEAT_SCHEDULE = {
    "sync-due-gmail-accounts": {
        "task": "gmail.sync_due_accounts",
        "schedule": int(os.environ.get("GMAIL_MONITOR_TICK_SECONDS", "300")),
    },
}

# Private AI provider
AI_PROVIDER_ORDER = os.environ.get("AI_PROVIDER_ORDER", "ollama")
AI_MESSAGE_TIME_BUDGET_SECONDS = int(os.environ.get("AI_MESSAGE_TIME_BUDGET_SECONDS", "30"))
AI_PROCESSING_STALE_SECONDS = int(os.environ.get("AI_PROCESSING_STALE_SECONDS", str(max(90, AI_MESSAGE_TIME_BUDGET_SECONDS * 3))))
AI_QUEUE_MAX_BATCH = int(os.environ.get("AI_QUEUE_MAX_BATCH", "30"))
AI_QUEUE_MAX_PARALLEL_PER_ACCOUNT = int(os.environ.get("AI_QUEUE_MAX_PARALLEL_PER_ACCOUNT", "2"))
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:1.5b")
OLLAMA_TIMEOUT_SECONDS = int(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "180"))
OLLAMA_DISABLE_ON_ERROR_SECONDS = int(os.environ.get("OLLAMA_DISABLE_ON_ERROR_SECONDS", "120"))
OLLAMA_PULL_ON_START = os.environ.get("OLLAMA_PULL_ON_START", "true").lower() == "true"
OLLAMA_MODEL_CHECK_SECONDS = int(os.environ.get("OLLAMA_MODEL_CHECK_SECONDS", "60"))
OLLAMA_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "2048"))
OLLAMA_NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "480"))
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "10m")


# Billing / purchase site
PURCHASE_SITE_URL = os.environ.get("PURCHASE_SITE_URL", "http://localhost:5174")
BIZGUARD_APP_URL = os.environ.get("BIZGUARD_APP_URL", "http://localhost:5173")
BILLING_FAKE_MODE = os.environ.get("BILLING_FAKE_MODE", "False").lower() == "true"
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")

