from django.test import TestCase
from django.http import HttpResponse
from django.urls import path, include
from django.urls.resolvers import RoutePattern
from django_magic_authorization.urls import protected_path
from django_magic_authorization.middleware import MagicAuthorizationRouter


class PathProtectTests(TestCase):
    """Test the protected_path() URL wrapper function."""

    def view(request):
        return HttpResponse("test")

    def test_protected_path_flags_view(self):
        """protected_path() should set _django_magic_authorization flag on the pattern."""
        pattern = protected_path("test/", PathProtectTests.view)
        self.assertTrue(hasattr(pattern, "_django_magic_authorization"))
        self.assertTrue(pattern._django_magic_authorization)

    def test_protected_path_returns_urlpattern(self):
        """protected_path() should return a URLPattern object."""
        pattern = protected_path("test/", PathProtectTests.view)
        self.assertEqual(str(pattern.pattern), "test/")
        self.assertEqual(pattern.callback, PathProtectTests.view)

    def test_protected_path_with_kwargs(self):
        """protected_path() should pass through kwargs to path()."""
        pattern = protected_path("test/", PathProtectTests.view, name="test_name")
        self.assertEqual(pattern.name, "test_name")

    def test_protected_path_with_protect_fn(self):
        """protected_path() should set _django_magic_authorization_fn attribute."""

        def protect_fn(kwargs):
            return kwargs.get("visibility") == "private"

        pattern = protected_path(
            "<str:visibility>/test/", PathProtectTests.view, protect_fn=protect_fn
        )
        self.assertTrue(hasattr(pattern, "_django_magic_authorization_fn"))
        self.assertEqual(pattern._django_magic_authorization_fn, protect_fn)

    def test_protected_path_without_protect_fn(self):
        """protected_path() should set _django_magic_authorization_fn to None when not provided."""
        pattern = protected_path("test/", PathProtectTests.view)
        self.assertTrue(hasattr(pattern, "_django_magic_authorization_fn"))
        self.assertIsNone(pattern._django_magic_authorization_fn)


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


class RouterTests(TestCase):
    """Test the MagicAuthorizationRouter singleton."""

    def test_router_is_singleton(self):
        """MagicAuthorizationRouter should return the same instance."""
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
