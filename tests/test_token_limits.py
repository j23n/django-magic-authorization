from datetime import timedelta
from io import StringIO

from django.test import TestCase, RequestFactory
from django.core.management import call_command
from django.http import HttpResponse
from django.urls.resolvers import RoutePattern
from django.utils import timezone
from django_magic_authorization.middleware import (
    MagicAuthorizationRouter,
    MagicAuthorizationMiddleware,
)
from django_magic_authorization.models import AccessToken


class TokenExpirationTests(TestCase):
    """Test token expiration and usage limit enforcement."""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = MagicAuthorizationMiddleware(
            get_response=lambda r: HttpResponse("OK")
        )

        router = MagicAuthorizationRouter()
        router._registry.clear()
        test_pattern = RoutePattern("protected/", name=None)
        router.register("", test_pattern)

    def test_token_without_expiration_is_allowed(self):
        """Token with expires_at=None should be accepted (backwards compatible)."""
        token = AccessToken.objects.create(
            description="No expiry", path="protected/", is_valid=True
        )
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 302)

    def test_token_with_future_expiration_is_allowed(self):
        """Token with expires_at in the future should be accepted."""
        token = AccessToken.objects.create(
            description="Future expiry",
            path="protected/",
            is_valid=True,
            expires_at=timezone.now() + timedelta(hours=1),
        )
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 302)

    def test_token_with_past_expiration_is_rejected(self):
        """Token with expires_at in the past should be rejected."""
        token = AccessToken.objects.create(
            description="Expired",
            path="protected/",
            is_valid=True,
            expires_at=timezone.now() - timedelta(hours=1),
        )
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_token_without_max_uses_is_allowed(self):
        """Token with max_uses=None should be accepted (backwards compatible)."""
        token = AccessToken.objects.create(
            description="Unlimited", path="protected/", is_valid=True
        )
        token.times_accessed = 999
        token.save()
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 302)

    def test_token_under_max_uses_is_allowed(self):
        """Token with times_accessed < max_uses should be accepted."""
        token = AccessToken.objects.create(
            description="Limited",
            path="protected/",
            is_valid=True,
            max_uses=5,
        )
        token.times_accessed = 3
        token.save()
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 302)

    def test_token_at_max_uses_is_rejected(self):
        """Token with times_accessed == max_uses should be rejected."""
        token = AccessToken.objects.create(
            description="Exhausted",
            path="protected/",
            is_valid=True,
            max_uses=3,
        )
        token.times_accessed = 3
        token.save()
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_token_over_max_uses_is_rejected(self):
        """Token with times_accessed > max_uses should be rejected."""
        token = AccessToken.objects.create(
            description="Over limit",
            path="protected/",
            is_valid=True,
            max_uses=2,
        )
        token.times_accessed = 5
        token.save()
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_single_use_token(self):
        """Token with max_uses=1 should work once then be rejected."""
        token = AccessToken.objects.create(
            description="Single use",
            path="protected/",
            is_valid=True,
            max_uses=1,
        )

        # First use succeeds
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 302)

        # Second use fails (times_accessed is now 1 == max_uses)
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_expired_token_with_remaining_uses_is_rejected(self):
        """Expired token should be rejected even if max_uses not reached."""
        token = AccessToken.objects.create(
            description="Expired with uses left",
            path="protected/",
            is_valid=True,
            expires_at=timezone.now() - timedelta(hours=1),
            max_uses=100,
        )
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_exhausted_token_with_future_expiry_is_rejected(self):
        """Exhausted token should be rejected even if not yet expired."""
        token = AccessToken.objects.create(
            description="Exhausted with time left",
            path="protected/",
            is_valid=True,
            expires_at=timezone.now() + timedelta(hours=1),
            max_uses=1,
        )
        token.times_accessed = 1
        token.save()
        request = self.factory.get(f"/protected/?token={token.token}")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)


class CleanupExpiredTokensTests(TestCase):
    """Test the cleanup_expired_tokens management command."""

    def test_deletes_expired_tokens(self):
        """Command should delete tokens past their expires_at."""
        expired = AccessToken.objects.create(
            description="Expired",
            path="p/",
            is_valid=True,
            expires_at=timezone.now() - timedelta(hours=1),
        )
        alive = AccessToken.objects.create(
            description="Alive",
            path="p/",
            is_valid=True,
            expires_at=timezone.now() + timedelta(hours=1),
        )

        out = StringIO()
        call_command("cleanup_expired_tokens", stdout=out)

        self.assertFalse(AccessToken.objects.filter(pk=expired.pk).exists())
        self.assertTrue(AccessToken.objects.filter(pk=alive.pk).exists())
        self.assertIn("1", out.getvalue())

    def test_deletes_exhausted_tokens(self):
        """Command should delete tokens that have reached max_uses."""
        exhausted = AccessToken.objects.create(
            description="Exhausted",
            path="p/",
            is_valid=True,
            max_uses=2,
        )
        exhausted.times_accessed = 2
        exhausted.save()

        still_valid = AccessToken.objects.create(
            description="Still valid",
            path="p/",
            is_valid=True,
            max_uses=10,
        )
        still_valid.times_accessed = 3
        still_valid.save()

        out = StringIO()
        call_command("cleanup_expired_tokens", stdout=out)

        self.assertFalse(AccessToken.objects.filter(pk=exhausted.pk).exists())
        self.assertTrue(AccessToken.objects.filter(pk=still_valid.pk).exists())

    def test_leaves_unlimited_tokens(self):
        """Command should not delete tokens with no expiration or max_uses."""
        unlimited = AccessToken.objects.create(
            description="Unlimited", path="p/", is_valid=True
        )

        out = StringIO()
        call_command("cleanup_expired_tokens", stdout=out)

        self.assertTrue(AccessToken.objects.filter(pk=unlimited.pk).exists())
        self.assertIn("0", out.getvalue())
