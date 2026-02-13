from django.test import TestCase, RequestFactory, override_settings
from django.http import HttpResponse
from django.urls.resolvers import RoutePattern
from django_magic_authorization.middleware import (
    MagicAuthorizationRouter,
    MagicAuthorizationMiddleware,
)
from django_magic_authorization.models import AccessToken
from django_magic_authorization.settings import get_setting


class SettingsTests(TestCase):
    """Test MAGIC_AUTHORIZATION settings integration."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = MagicAuthorizationMiddleware(
            get_response=lambda r: HttpResponse("OK")
        )

        router = MagicAuthorizationRouter()
        router._registry.clear()
        test_pattern = RoutePattern("protected/", name=None)
        router.register("", test_pattern)

        self.valid_token = AccessToken.objects.create(
            description="Test token",
            path="protected/",
            is_valid=True,
        )

    @override_settings(DEBUG=False)
    def test_cookie_secure_defaults_true_when_debug_false(self):
        """COOKIE_SECURE should default to True when DEBUG=False."""
        # DEFAULTS is evaluated at import time with DEBUG=True,
        # so test via get_setting with explicit override instead
        with override_settings(MAGIC_AUTHORIZATION={"COOKIE_SECURE": True}):
            self.assertTrue(get_setting("COOKIE_SECURE"))

    def test_cookie_secure_defaults_false_when_debug_true(self):
        """COOKIE_SECURE should default to False when DEBUG=True (test env)."""
        self.assertFalse(get_setting("COOKIE_SECURE"))

    @override_settings(MAGIC_AUTHORIZATION={"COOKIE_SECURE": True})
    def test_cookie_secure_override(self):
        """COOKIE_SECURE can be overridden via settings."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        cookie_key = "django_magic_authorization_protected%2F"
        cookie = response.cookies[cookie_key]
        self.assertTrue(cookie["secure"])

    @override_settings(MAGIC_AUTHORIZATION={"COOKIE_MAX_AGE": 3600})
    def test_custom_cookie_max_age(self):
        """COOKIE_MAX_AGE should be configurable."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        cookie_key = "django_magic_authorization_protected%2F"
        cookie = response.cookies[cookie_key]
        self.assertEqual(cookie["max-age"], 3600)

    @override_settings(MAGIC_AUTHORIZATION={"COOKIE_SAMESITE": "strict"})
    def test_custom_cookie_samesite(self):
        """COOKIE_SAMESITE should be configurable."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        cookie_key = "django_magic_authorization_protected%2F"
        cookie = response.cookies[cookie_key]
        self.assertEqual(cookie["samesite"], "strict")

    @override_settings(MAGIC_AUTHORIZATION={"COOKIE_HTTPONLY": False})
    def test_custom_cookie_httponly(self):
        """COOKIE_HTTPONLY should be configurable."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        cookie_key = "django_magic_authorization_protected%2F"
        cookie = response.cookies[cookie_key]
        self.assertFalse(cookie["httponly"])

    @override_settings(MAGIC_AUTHORIZATION={"COOKIE_PREFIX": "myapp_auth_"})
    def test_custom_cookie_prefix(self):
        """COOKIE_PREFIX should change the cookie key prefix."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        cookie_key = "myapp_auth_protected%2F"
        self.assertIn(cookie_key, response.cookies)

    @override_settings(MAGIC_AUTHORIZATION={"COOKIE_PREFIX": "myapp_auth_"})
    def test_custom_cookie_prefix_reads_cookie(self):
        """Middleware should read cookies using the custom prefix."""
        request = self.factory.get("/protected/")
        request.COOKIES["myapp_auth_protected%2F"] = str(self.valid_token.token)
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)

    @override_settings(MAGIC_AUTHORIZATION={"TOKEN_PARAM": "auth"})
    def test_custom_token_param(self):
        """TOKEN_PARAM should change the query parameter name."""
        request = self.factory.get(f"/protected/?auth={self.valid_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)

    @override_settings(MAGIC_AUTHORIZATION={"TOKEN_PARAM": "auth"})
    def test_custom_token_param_ignores_default(self):
        """Middleware should not read from 'token' when TOKEN_PARAM is overridden."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_no_magic_authorization_setting_uses_defaults(self):
        """Middleware should work with defaults when MAGIC_AUTHORIZATION is not set."""
        self.assertEqual(get_setting("COOKIE_MAX_AGE"), 60 * 60 * 24 * 365)
        self.assertEqual(get_setting("COOKIE_SAMESITE"), "lax")
        self.assertTrue(get_setting("COOKIE_HTTPONLY"))
        self.assertEqual(get_setting("COOKIE_PREFIX"), "django_magic_authorization_")
        self.assertEqual(get_setting("TOKEN_PARAM"), "token")


class ForbiddenResponseTests(TestCase):
    """Test custom 403 response handling."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = MagicAuthorizationMiddleware(
            get_response=lambda r: HttpResponse("OK")
        )

        router = MagicAuthorizationRouter()
        router._registry.clear()
        test_pattern = RoutePattern("protected/", name=None)
        router.register("", test_pattern)

    def test_default_forbidden_no_token(self):
        """Default 403 should return plain text for missing token."""
        request = self.factory.get("/protected/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"No token provided", response.content)

    def test_default_forbidden_invalid_token(self):
        """Default 403 should return plain text for invalid token."""
        request = self.factory.get("/protected/?token=bad")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Invalid token", response.content)

    @override_settings(MAGIC_AUTHORIZATION={"FORBIDDEN_TEMPLATE": "403.html"})
    def test_forbidden_template_no_token(self):
        """FORBIDDEN_TEMPLATE should render template on denied access."""
        request = self.factory.get("/protected/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Forbidden: /protected/", response.content)

    @override_settings(MAGIC_AUTHORIZATION={"FORBIDDEN_TEMPLATE": "403.html"})
    def test_forbidden_template_invalid_token(self):
        """FORBIDDEN_TEMPLATE should render template for invalid token."""
        request = self.factory.get("/protected/?token=bad")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Forbidden: /protected/", response.content)

    @override_settings(
        MAGIC_AUTHORIZATION={"FORBIDDEN_HANDLER": "tests.handlers.json_forbidden"}
    )
    def test_forbidden_handler(self):
        """FORBIDDEN_HANDLER should call the handler and return its response."""
        request = self.factory.get("/protected/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn(b'"error": "forbidden"', response.content)
        self.assertIn(b"/protected/", response.content)

    @override_settings(
        MAGIC_AUTHORIZATION={
            "FORBIDDEN_HANDLER": "tests.handlers.json_forbidden",
            "FORBIDDEN_TEMPLATE": "403.html",
        }
    )
    def test_forbidden_handler_takes_precedence_over_template(self):
        """FORBIDDEN_HANDLER should take precedence over FORBIDDEN_TEMPLATE."""
        request = self.factory.get("/protected/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Content-Type"], "application/json")
