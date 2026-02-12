from django.conf import settings

DEFAULTS = {
    "COOKIE_SECURE": not settings.DEBUG,
    "COOKIE_MAX_AGE": 60 * 60 * 24 * 365,  # 1 year
    "COOKIE_SAMESITE": "lax",
    "COOKIE_HTTPONLY": True,
    "COOKIE_PREFIX": "django_magic_authorization_",
    "TOKEN_PARAM": "token",
}


def get_setting(name):
    user_settings = getattr(settings, "MAGIC_AUTHORIZATION", {})
    if name in user_settings:
        return user_settings[name]
    return DEFAULTS[name]
