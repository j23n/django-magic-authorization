import uuid

from django.test import TestCase, RequestFactory
from django.http import HttpResponse
from django.urls.resolvers import RoutePattern
from django_magic_authorization.middleware import (
    MagicAuthorizationRouter,
    MagicAuthorizationMiddleware,
)
from django_magic_authorization.models import AccessToken


class PathMatchingTests(TestCase):
    """Test middleware path matching: static, dynamic, prefix, trailing slash, subpaths, protect_fn."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = MagicAuthorizationMiddleware(
            get_response=lambda r: HttpResponse("OK")
        )
        router = MagicAuthorizationRouter()
        router._registry.clear()
        test_pattern = RoutePattern("protected/", name=None)
        router.register("", test_pattern)

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

        self.assertEqual(response.status_code, 302)

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

    def test_middleware_protect_fn_allows_non_matching_variant(self):
        """Middleware with protect_fn should allow non-matching URL variants without token."""
        router = MagicAuthorizationRouter()

        def protect_fn(kwargs):
            return kwargs.get("visibility") == "private"

        content_pattern = RoutePattern("<str:visibility>/<str:post>/", name=None)
        router.register("", content_pattern, protect_fn=protect_fn)

        # Public variant should not require token
        request = self.factory.get("/public/my-post/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)

    def test_middleware_protect_fn_blocks_matching_variant_without_token(self):
        """Middleware with protect_fn should block matching URL variants without token."""
        router = MagicAuthorizationRouter()

        def protect_fn(kwargs):
            return kwargs.get("visibility") == "private"

        content_pattern = RoutePattern("<str:visibility>/<str:post>/", name=None)
        router.register("", content_pattern, protect_fn=protect_fn)

        # Private variant should require token
        request = self.factory.get("/private/my-post/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_protect_fn_allows_matching_variant_with_valid_token(self):
        """Middleware with protect_fn should allow matching variants with valid token."""
        router = MagicAuthorizationRouter()

        def protect_fn(kwargs):
            return kwargs.get("visibility") == "private"

        content_pattern = RoutePattern("<str:visibility>/<str:post>/", name=None)
        router.register("", content_pattern, protect_fn=protect_fn)

        valid_token = AccessToken.objects.create(
            description="Private content token",
            path="<str:visibility>/<str:post>/",
            is_valid=True,
        )

        # Private variant with valid token should redirect to strip token
        request = self.factory.get(f"/private/my-post/?token={valid_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)

    def test_middleware_protect_fn_with_complex_logic(self):
        """Middleware should handle protect_fn with complex conditional logic."""
        router = MagicAuthorizationRouter()

        def protect_fn(kwargs):
            visibility = kwargs.get("visibility")
            category = kwargs.get("category", "")
            return visibility == "private" or category == "confidential"

        content_pattern = RoutePattern(
            "<str:visibility>/<str:category>/<str:post>/", name=None
        )
        router.register("", content_pattern, protect_fn=protect_fn)

        # Should allow public/general/my-post
        request = self.factory.get("/public/general/my-post/")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

        # Should block private/general/my-post (visibility=private)
        request = self.factory.get("/private/general/my-post/")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

        # Should block public/confidential/my-post (category=confidential)
        request = self.factory.get("/public/confidential/my-post/")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_middleware_protect_fn_exception_fails_safe(self):
        """Middleware should fail safe (protect) when protect_fn raises exception."""
        router = MagicAuthorizationRouter()

        def protect_fn(kwargs):
            # This will raise KeyError if 'visibility' is missing
            return kwargs["visibility"] == "private"

        # Pattern without visibility parameter - will cause exception
        content_pattern = RoutePattern("<str:post>/", name=None)
        router.register("", content_pattern, protect_fn=protect_fn)

        # Should fail safe and protect the path
        request = self.factory.get("/my-post/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_blocks_prefixed_path_without_token(self):
        """Middleware should block paths registered with a non-empty prefix (from include())."""
        router = MagicAuthorizationRouter()
        pattern = RoutePattern("secret/", name=None)
        router.register("api/v1/", pattern)

        request = self.factory.get("/api/v1/secret/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_allows_prefixed_path_with_valid_token(self):
        """Middleware should allow prefixed paths with a valid token and set correct cookie."""
        router = MagicAuthorizationRouter()
        pattern = RoutePattern("secret/", name=None)
        router.register("api/v1/", pattern)

        token = AccessToken.objects.create(
            description="Prefixed path token",
            path="api/v1/secret/",
            is_valid=True,
        )

        request = self.factory.get(f"/api/v1/secret/?token={token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)

        # Merged from test_middleware_prefixed_path_sets_cookie
        cookie_key = "django_magic_authorization_api%2Fv1%2Fsecret%2F"
        self.assertIn(cookie_key, response.cookies)

        # Merged from test_middleware_cookie_path_prefixed_pattern
        self.assertEqual(response.cookies[cookie_key]["path"], "/api/v1/secret/")

    def test_middleware_blocks_deeply_nested_prefixed_path(self):
        """Middleware should block deeply nested prefixed paths without token."""
        router = MagicAuthorizationRouter()
        pattern = RoutePattern("deep/", name=None)
        router.register("top/mid/", pattern)

        request = self.factory.get("/top/mid/deep/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)

    def test_middleware_allows_unrelated_path_with_similar_prefix(self):
        """Middleware should not block paths that don't match the prefix + pattern."""
        router = MagicAuthorizationRouter()
        pattern = RoutePattern("secret/", name=None)
        router.register("api/v1/", pattern)

        request = self.factory.get("/api/v2/secret/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)

    def test_middleware_prefixed_dynamic_pattern(self):
        """Middleware should block prefixed dynamic patterns without token."""
        router = MagicAuthorizationRouter()
        pattern = RoutePattern("<int:year>/<str:slug>/", name=None)
        router.register("blog/", pattern)

        request = self.factory.get("/blog/2024/my-post/")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)


class TokenValidationTests(TestCase):
    """Test middleware token validation and UUID handling."""

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
        """Middleware should redirect to strip token from URL on valid query-param token."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/protected/")

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

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.valid_token.times_accessed, 1)
        self.assertIsNotNone(self.valid_token.last_accessed)

    def test_middleware_redirect_preserves_extra_query_params(self):
        """Middleware should preserve other query params when stripping token on redirect."""
        request = self.factory.get(
            f"/protected/?foo=bar&token={self.valid_token.token}&baz=qux"
        )
        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)
        location = response["Location"]
        self.assertIn("/protected/", location)
        self.assertIn("foo=bar", location)
        self.assertIn("baz=qux", location)
        self.assertNotIn("token=", location)

    def test_middleware_prefers_url_token_over_cookie(self):
        """Middleware should check URL token first, then fall back to cookie."""
        # Set invalid cookie but valid URL token
        fake_uuid = uuid.uuid4()
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        request.COOKIES["django_magic_authorization_protected%2F"] = str(fake_uuid)

        response = self.middleware(request)
        # Should succeed because URL token is valid (redirect to strip token)
        self.assertEqual(response.status_code, 302)


class CookieTests(TestCase):
    """Test middleware cookie behavior: set, read, path scoping."""

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

    def test_middleware_sets_cookie_on_valid_token(self):
        """Middleware should set cookie on redirect response after query-param validation."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)
        # Check cookie is set (protected/ is URL-encoded as protected%2F)
        cookie_key = "django_magic_authorization_protected%2F"
        self.assertIn(cookie_key, response.cookies)
        self.assertEqual(
            str(response.cookies[cookie_key].value), str(self.valid_token.token)
        )

    def test_middleware_cookie_settings(self):
        """Middleware should set cookie with correct default settings."""
        request = self.factory.get(f"/protected/?token={self.valid_token.token}")
        response = self.middleware(request)

        cookie_key = "django_magic_authorization_protected%2F"
        cookie = response.cookies[cookie_key]

        # Verify default settings (DEBUG=True in tests, so secure=False)
        self.assertTrue(cookie["httponly"])
        self.assertFalse(cookie["secure"])
        self.assertEqual(cookie["samesite"], "lax")
        self.assertEqual(cookie["max-age"], 60 * 60 * 24 * 365)  # 1 year
        self.assertEqual(cookie["path"], "/protected/")

    def test_middleware_allows_access_with_valid_cookie(self):
        """Middleware should allow access with valid cookie (no token in URL)."""
        # Create request with cookie, no token in URL
        request = self.factory.get("/protected/")
        request.COOKIES["django_magic_authorization_protected%2F"] = str(
            self.valid_token.token
        )

        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_middleware_blocks_access_with_invalid_cookie(self):
        """Middleware should block access with invalid cookie."""
        fake_uuid = uuid.uuid4()
        request = self.factory.get("/protected/")
        request.COOKIES["django_magic_authorization_protected%2F"] = str(fake_uuid)

        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_middleware_cookie_path_dynamic_pattern(self):
        """Cookie path should be the static prefix for dynamic patterns."""
        router = MagicAuthorizationRouter()
        blog_pattern = RoutePattern("blog/<int:year>/<str:slug>/", name=None)
        router.register("", blog_pattern)

        blog_token = AccessToken.objects.create(
            description="Blog token",
            path="blog/<int:year>/<str:slug>/",
            is_valid=True,
        )

        request = self.factory.get(f"/blog/2024/my-post/?token={blog_token.token}")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 302)

        cookie_key = (
            "django_magic_authorization_blog%2F%3Cint%3Ayear%3E%2F%3Cstr%3Aslug%3E%2F"
        )
        # Merged from test_middleware_cookie_scoped_to_protected_path
        self.assertIn(cookie_key, response.cookies)
        self.assertEqual(response.cookies[cookie_key]["path"], "/blog/")

    def test_middleware_cookie_path_fully_dynamic_pattern(self):
        """Cookie path should be / when pattern starts with a dynamic segment."""
        router = MagicAuthorizationRouter()
        pattern = RoutePattern("<str:visibility>/<str:post>/", name=None)
        router.register("", pattern)

        token = AccessToken.objects.create(
            description="Dynamic token",
            path="<str:visibility>/<str:post>/",
            is_valid=True,
        )

        request = self.factory.get(f"/private/my-post/?token={token.token}")
        response = self.middleware(request)

        cookie_key = (
            "django_magic_authorization_%3Cstr%3Avisibility%3E%2F%3Cstr%3Apost%3E%2F"
        )
        self.assertEqual(response.cookies[cookie_key]["path"], "/")

    def test_middleware_cookie_works_across_pattern_variants(self):
        """Middleware cookie should work for different URLs matching the same pattern."""
        router = MagicAuthorizationRouter()
        blog_pattern = RoutePattern("blog/<int:year>/<str:slug>/", name=None)
        router.register("", blog_pattern)

        blog_token = AccessToken.objects.create(
            description="Blog token",
            path="blog/<int:year>/<str:slug>/",
            is_valid=True,
        )

        # Access first post with token in URL - should redirect and set cookie
        request = self.factory.get(f"/blog/2024/first-post/?token={blog_token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 302)

        # Access different post with cookie only (no token in URL)
        request2 = self.factory.get("/blog/2025/second-post/")
        request2.COOKIES[
            "django_magic_authorization_blog%2F%3Cint%3Ayear%3E%2F%3Cstr%3Aslug%3E%2F"
        ] = str(blog_token.token)
        response2 = self.middleware(request2)

        # Should work because cookie is scoped to the pattern
        self.assertEqual(response2.status_code, 200)
