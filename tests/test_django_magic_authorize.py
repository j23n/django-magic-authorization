from django.test import TestCase, RequestFactory
from django.http import HttpResponse
from django.urls import path, include
from django_magic_authorize.urls import path_protect
from django_magic_authorize.middleware import (
    MagicAuthRouter,
    walk_patterns,
    discover_protected_paths,
    MagicAuthMiddleware,
)
from django_magic_authorize.models import AccessToken
import uuid


class PathProtectTests(TestCase):
    """Test the path_protect() URL wrapper function."""

    def test_path_protect_flags_view(self):
        """path_protect() should set _magic_authorize_protected flag on the view."""
        view = lambda request: HttpResponse("test")
        pattern = path_protect("test/", view)
        self.assertTrue(hasattr(pattern.callback, "_magic_authorize_protected"))
        self.assertTrue(pattern.callback._magic_authorize_protected)

    def test_path_protect_returns_urlpattern(self):
        """path_protect() should return a URLPattern object."""
        view = lambda request: HttpResponse("test")
        pattern = path_protect("test/", view)
        self.assertEqual(str(pattern.pattern), "test/")
        self.assertEqual(pattern.callback, view)

    def test_path_protect_with_kwargs(self):
        """path_protect() should pass through kwargs to path()."""
        view = lambda request: HttpResponse("test")
        pattern = path_protect("test/", view, name="test_name")
        self.assertEqual(pattern.name, "test_name")


class URLTreeWalkerTests(TestCase):
    """Test the URL tree walker that discovers protected paths."""

    def setUp(self):
        router = MagicAuthRouter()
        router._registry.clear()

    def test_discover_protected_path(self):
        """URL walker should discover and register path_protect() patterns."""
        patterns = [
            path("public/", lambda request: HttpResponse("public")),
            path_protect("private/", lambda request: HttpResponse("private")),
        ]

        router = MagicAuthRouter()
        walk_patterns(patterns, router, prefix="")

        self.assertIn("/private/", router._registry)
        self.assertNotIn("/public/", router._registry)

    def test_discover_nested_includes(self):
        """URL walker should handle nested include() with proper path resolution."""
        deep_patterns = [path_protect("deep/", lambda request: HttpResponse("deep"))]
        mid_patterns = [path("mid/", include(deep_patterns))]
        patterns = [path("top/", include(mid_patterns))]

        router = MagicAuthRouter()
        walk_patterns(patterns, router, prefix="")

        self.assertIn("/top/mid/deep/", router._registry)

    def test_path_normalization_adds_leading_slash(self):
        """Router should normalize paths by adding leading slash."""
        router = MagicAuthRouter()
        router.register("test/path/")

        self.assertIn("/test/path/", router._registry)


class MiddlewareTokenValidationTests(TestCase):
    """Test middleware token validation and UUID handling."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = MagicAuthMiddleware(get_response=lambda r: HttpResponse("OK"))

        # Clear and set up registry
        router = MagicAuthRouter()
        router._registry.clear()
        router.register("/protected/")

        # Create a valid token
        self.valid_token = AccessToken.objects.create(
            description="Test token",
            path="/protected/",
            is_valid=True,
        )

    def test_middleware_allows_unprotected_paths(self):
        """Middleware should allow access to unprotected paths without token."""
        request = self.factory.get("/public/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)

    def test_middleware_blocks_protected_path_without_token(self):
        """Middleware should block protected paths when no token provided."""
        request = self.factory.get("/protected/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_blocks_invalid_uuid_format(self):
        """Middleware should block requests with invalid UUID token format."""
        request = self.factory.get("/protected/?token=invalid-uuid")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_blocks_nonexistent_token(self):
        """Middleware should block requests with valid UUID but nonexistent token."""
        fake_uuid = uuid.uuid4()
        request = self.factory.get(f"/protected/?token={fake_uuid}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_allows_valid_token(self):
        """Middleware should allow access with valid token."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)

    def test_middleware_blocks_invalid_token(self):
        """Middleware should block access when token is marked invalid."""
        self.valid_token.is_valid = False
        self.valid_token.save()

        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_blocks_wrong_path_token(self):
        """Middleware should block token used on wrong path."""
        request = self.factory.get(f"/other-protected/?token={self.valid_token.token}")

        # Register the other path
        router = MagicAuthRouter()
        router.register("/other-protected/")

        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_middleware_updates_access_stats(self):
        """Middleware should update times_accessed and last_accessed on valid access."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")

        # Initial state
        self.assertEqual(self.valid_token.times_accessed, 0)
        self.assertIsNone(self.valid_token.last_accessed)

        response = self.middleware(request)

        # Refresh from DB
        self.valid_token.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.valid_token.times_accessed, 1)
        self.assertIsNotNone(self.valid_token.last_accessed)


class MagicAuthRouterTests(TestCase):
    """Test the MagicAuthRouter singleton."""

    def test_router_is_singleton(self):
        """MagicAuthRouter should return the same instance."""
        router1 = MagicAuthRouter()
        router2 = MagicAuthRouter()

        self.assertIs(router1, router2)

    def test_router_registry_persists(self):
        """Registry should persist across router instances."""
        router1 = MagicAuthRouter()
        router1._registry.clear()
        router1.register("/test/")

        router2 = MagicAuthRouter()
        self.assertIn("/test/", router2._registry)
