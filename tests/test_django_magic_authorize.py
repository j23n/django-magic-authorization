from django.test import TestCase, RequestFactory
from django.http import HttpResponse
from django.urls import path, include
from django.urls.resolvers import RoutePattern
from django_magic_authorization.urls import protected_path
from django_magic_authorization.middleware import (
    MagicAuthorizationRouter,
    MagicAuthorizationMiddleware,
)
from django_magic_authorization.admin import AccessTokenAdmin
from django_magic_authorization.models import AccessToken
from django.contrib.admin.sites import AdminSite

import uuid


class PathProtectTests(TestCase):
    """Test the protected_path() URL wrapper function."""

    def test_protected_path_flags_view(self):
        """protected_path() should set _django_magic_authorization flag on the pattern."""
        view = lambda request: HttpResponse("test")
        pattern = protected_path("test/", view)
        self.assertTrue(hasattr(pattern, "_django_magic_authorization"))
        self.assertTrue(pattern._django_magic_authorization)

    def test_protected_path_returns_urlpattern(self):
        """protected_path() should return a URLPattern object."""
        view = lambda request: HttpResponse("test")
        pattern = protected_path("test/", view)
        self.assertEqual(str(pattern.pattern), "test/")
        self.assertEqual(pattern.callback, view)

    def test_protected_path_with_kwargs(self):
        """protected_path() should pass through kwargs to path()."""
        view = lambda request: HttpResponse("test")
        pattern = protected_path("test/", view, name="test_name")
        self.assertEqual(pattern.name, "test_name")


class URLTreeWalkerTests(TestCase):
    """Test the URL tree walker that discovers protected paths."""

    def setUp(self):
        router = MagicAuthorizationRouter()
        router._registry.clear()

    def test_discover_protected_path(self):
        """URL walker should discover and register protected_path() patterns."""
        patterns = [
            path("public/", lambda request: HttpResponse("public")),
            protected_path("private/", lambda request: HttpResponse("private")),
        ]

        router = MagicAuthorizationRouter()
        router.walk_patterns(patterns)

        registry_paths = router.get_protected_paths()
        self.assertIn("private/", registry_paths)
        self.assertNotIn("public/", registry_paths)

    def test_discover_nested_includes(self):
        """URL walker should handle nested include() with proper path resolution."""
        deep_patterns = [protected_path("deep/", lambda request: HttpResponse("deep"))]
        mid_patterns = [path("mid/", include(deep_patterns))]
        patterns = [path("top/", include(mid_patterns))]

        router = MagicAuthorizationRouter()
        router.walk_patterns(patterns)

        registry_paths = router.get_protected_paths()
        self.assertIn("top/mid/deep/", registry_paths)

    def test_path_normalization_adds_leading_slash(self):
        """Router should normalize paths by adding leading slash."""
        router = MagicAuthorizationRouter()
        test_pattern = RoutePattern("test/path/", name=None)
        router.register("", test_pattern)

        registry_paths = router.get_protected_paths()
        self.assertIn("test/path/", registry_paths)


class MiddlewareTokenValidationTests(TestCase):
    """Test middleware token validation and UUID handling."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = MagicAuthorizationMiddleware(get_response=lambda r: HttpResponse("OK"))

        router = MagicAuthorizationRouter()
        router._registry.clear()
        test_pattern = RoutePattern("protected/", name=None)
        router.register("", test_pattern)

        self.valid_token = AccessToken.objects.create(
            description="Test token",
            path="protected/",
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

        router = MagicAuthorizationRouter()
        other_pattern = RoutePattern("other-protected/", name=None)
        router.register("", other_pattern)

        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_middleware_updates_access_stats(self):
        """Middleware should update times_accessed and last_accessed on valid access."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")

        self.assertEqual(self.valid_token.times_accessed, 0)
        self.assertIsNone(self.valid_token.last_accessed)

        response = self.middleware(request)

        self.valid_token.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.valid_token.times_accessed, 1)
        self.assertIsNotNone(self.valid_token.last_accessed)

    def test_middleware_path_matching_doesnt_match_prefix_only(self):
        """Middleware should not match /admin-panel when /admin is protected."""
        router = MagicAuthorizationRouter()
        admin_pattern = RoutePattern("admin", name=None)
        router.register("", admin_pattern)

        request = self.factory.get("/admin-panel/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)

    def test_middleware_path_matching_matches_subpaths(self):
        """Middleware should match /admin/users when /admin is protected."""
        router = MagicAuthorizationRouter()
        admin_pattern = RoutePattern("admin", name=None)
        router.register("", admin_pattern)

        request = self.factory.get("/admin/users/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_path_matching_with_trailing_slash(self):
        """Middleware with trailing slash pattern should match subpaths correctly."""
        router = MagicAuthorizationRouter()
        admin_pattern = RoutePattern("admin/", name=None)
        router.register("", admin_pattern)

        request = self.factory.get("/admin/panel/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_exact_match_without_trailing_slash(self):
        """Middleware should match exact path without trailing slash."""
        router = MagicAuthorizationRouter()
        admin_pattern = RoutePattern("admin", name=None)
        router.register("", admin_pattern)

        request = self.factory.get("/admin")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_dynamic_pattern_with_valid_params(self):
        """Middleware should match dynamic patterns with valid parameters."""
        router = MagicAuthorizationRouter()
        blog_pattern = RoutePattern("blog/<int:year>/<str:slug>/", name=None)
        router.register("", blog_pattern)

        valid_token = AccessToken.objects.create(
            description="Blog token",
            path="blog/<int:year>/<str:slug>/",
            is_valid=True,
        )

        request = self.factory.get(f"/blog/2024/my-post/?token={valid_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)

    def test_middleware_dynamic_pattern_blocks_without_token(self):
        """Middleware should block dynamic patterns without token."""
        router = MagicAuthorizationRouter()
        blog_pattern = RoutePattern("blog/<int:year>/<str:slug>/", name=None)
        router.register("", blog_pattern)

        request = self.factory.get("/blog/2024/my-post/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_dynamic_pattern_doesnt_match_prefix(self):
        """Middleware should not match similar but different paths."""
        router = MagicAuthorizationRouter()
        blog_pattern = RoutePattern("blog/<int:year>/<str:slug>/", name=None)
        router.register("", blog_pattern)

        request = self.factory.get("/blog-archive/2024/my-post/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)

    def test_middleware_dynamic_pattern_with_subpath(self):
        """Middleware should match subpaths of dynamic patterns."""
        router = MagicAuthorizationRouter()
        blog_pattern = RoutePattern("blog/<int:year>/", name=None)
        router.register("", blog_pattern)

        request = self.factory.get("/blog/2024/january/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_dynamic_pattern_exact_match(self):
        """Middleware should exactly match dynamic patterns."""
        router = MagicAuthorizationRouter()
        blog_pattern = RoutePattern("blog/<int:year>/<str:slug>/", name=None)
        router.register("", blog_pattern)

        request = self.factory.get("/blog/2024/my-post/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_dynamic_pattern_without_trailing_slash(self):
        """Middleware should handle dynamic patterns without trailing slash."""
        router = MagicAuthorizationRouter()
        api_pattern = RoutePattern("api/posts/<int:id>", name=None)
        router.register("", api_pattern)

        request = self.factory.get("/api/posts/123")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_dynamic_pattern_subpath_no_slash(self):
        """Middleware should match subpaths of dynamic patterns without trailing slash."""
        router = MagicAuthorizationRouter()
        api_pattern = RoutePattern("api/posts/<int:id>", name=None)
        router.register("", api_pattern)

        request = self.factory.get("/api/posts/123/comments")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_dynamic_pattern_no_prefix_match(self):
        """Middleware should not match when path has extra chars after pattern without slash."""
        router = MagicAuthorizationRouter()
        api_pattern = RoutePattern("api/posts/<int:id>", name=None)
        router.register("", api_pattern)

        request = self.factory.get("/api/posts/123extra")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)


class MagicAuthorizationRouterTests(TestCase):
    """Test the MagicAuthorizationRoutersingleton."""

    def test_router_is_singleton(self):
        """MagicAuthorizationRoutershould return the same instance."""
        router1 = MagicAuthorizationRouter()
        router2 = MagicAuthorizationRouter()

        self.assertIs(router1, router2)

    def test_router_registry_persists(self):
        """Registry should persist across router instances."""
        router1 = MagicAuthorizationRouter()
        router1._registry.clear()
        test_pattern = RoutePattern("test/", name=None)
        router1.register("", test_pattern)

        router2 = MagicAuthorizationRouter()
        registry_paths = router2.get_protected_paths()
        self.assertIn("test/", registry_paths)


class AdminTests(TestCase):
    """Test Django admin interface for AccessToken."""

    def setUp(self):
        self.site = AdminSite()
        self.admin = AccessTokenAdmin(AccessToken, self.site)

        router = MagicAuthorizationRouter()
        router._registry.clear()
        test_pattern = RoutePattern("protected/", name=None)
        router.register("", test_pattern)

        self.token = AccessToken.objects.create(
            description="Test token",
            path="protected/",
            is_valid=True,
        )

    def test_get_access_link_generates_correct_url(self):
        """get_access_link should generate correct URL with token."""
        link = self.admin.get_access_link(self.token)
        expected = f"protected/?token={self.token.token}"
        self.assertEqual(link, expected)

    def test_display_path_shows_registered_path(self):
        """display_path should show path normally when registered."""
        display = self.admin.display_path(self.token)
        self.assertEqual(display, "protected/")
        self.assertNotIn("❗", display)

    def test_display_path_shows_warning_for_unregistered_path(self):
        """display_path should show warning for unregistered paths."""
        self.token.path = "unregistered/"
        self.token.save()
        display = self.admin.display_path(self.token)
        self.assertIn("❗", display)
        self.assertIn("unregistered/", display)

    def test_access_token_form_path_choice_includes_protected_paths(self):
        """AccessTokenForm path_choice should include all protected paths from router."""
        from django_magic_authorization.admin import AccessTokenForm

        router = MagicAuthorizationRouter
