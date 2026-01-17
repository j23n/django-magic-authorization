"""
Django settings for running tests.
"""

SECRET_KEY = "test-secret-key-for-django-magic-authorization"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.admin",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django_magic_authorization",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

USE_TZ = True

# Required for URL resolution
ROOT_URLCONF = "tests.urls"

MIDDLEWARE = [
    "django_magic_authorization.middleware.MagicAuthorizationMiddleware",
]
