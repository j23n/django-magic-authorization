from django.test import TestCase
from django.urls.resolvers import RoutePattern
from django.contrib.admin.sites import AdminSite
from django_magic_authorization.admin import AccessTokenAdmin
from django_magic_authorization.middleware import MagicAuthorizationRouter
from django_magic_authorization.models import AccessToken


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

    def test_access_link_generates_correct_url(self):
        """access_link should generate correct URL with token."""
        link = self.admin.access_link(self.token)
        expected = f"protected/?token={self.token.token}"
        self.assertEqual(link, expected)

    def test_display_path_shows_registered_path(self):
        """display_path should show path normally when registered."""
        display = self.admin.display_path(self.token)
        self.assertEqual(display, "protected/")
        self.assertNotIn("\u2757", display)

    def test_display_path_shows_warning_for_unregistered_path(self):
        """display_path should show warning for unregistered paths."""
        self.token.path = "unregistered/"
        self.token.save()
        display = self.admin.display_path(self.token)
        self.assertIn("\u2757", display)
        self.assertIn("unregistered/", display)

    def test_access_token_form_path_choice_includes_protected_paths(self):
        """AccessTokenForm path_choice should include all protected paths from router."""
