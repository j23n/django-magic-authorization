from unittest.mock import MagicMock

from django.test import TestCase, RequestFactory
from django.http import HttpResponse
from django.urls.resolvers import RoutePattern
from django_magic_authorization.middleware import (
    MagicAuthorizationRouter,
    MagicAuthorizationMiddleware,
)
from django_magic_authorization.models import AccessToken
from django_magic_authorization.signals import access_granted, access_denied


class SignalTests(TestCase):
    """Test access_granted and access_denied signals."""

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

    def test_access_denied_signal_no_token(self):
        """access_denied signal should fire with reason='no_token'."""
        handler = MagicMock()
        access_denied.connect(handler)
        try:
            request = self.factory.get("/protected/")
            self.middleware(request)

            handler.assert_called_once()
            kwargs = handler.call_args[1]
            self.assertIsNone(kwargs["sender"])
            self.assertEqual(kwargs["path"], "/protected/")
            self.assertEqual(kwargs["reason"], "no_token")
        finally:
            access_denied.disconnect(handler)

    def test_access_denied_signal_invalid_token(self):
        """access_denied signal should fire with reason='invalid_token'."""
        handler = MagicMock()
        access_denied.connect(handler)
        try:
            request = self.factory.get("/protected/?token=bad")
            self.middleware(request)

            handler.assert_called_once()
            kwargs = handler.call_args[1]
            self.assertEqual(kwargs["reason"], "invalid_token")
        finally:
            access_denied.disconnect(handler)

    def test_access_granted_signal(self):
        """access_granted signal should fire with token and path on valid access."""
        handler = MagicMock()
        access_granted.connect(handler)
        try:
            request = self.factory.get(f"/protected/?token={self.valid_token.token}")
            self.middleware(request)

            handler.assert_called_once()
            kwargs = handler.call_args[1]
            self.assertEqual(kwargs["sender"], AccessToken)
            self.assertEqual(kwargs["path"], "protected/")
            self.assertEqual(kwargs["token"].pk, self.valid_token.pk)
        finally:
            access_granted.disconnect(handler)

    def test_access_granted_not_sent_on_deny(self):
        """access_granted signal should NOT fire when access is denied."""
        handler = MagicMock()
        access_granted.connect(handler)
        try:
            request = self.factory.get("/protected/")
            self.middleware(request)

            handler.assert_not_called()
        finally:
            access_granted.disconnect(handler)

    def test_access_denied_not_sent_on_grant(self):
        """access_denied signal should NOT fire when access is granted."""
        handler = MagicMock()
        access_denied.connect(handler)
        try:
            request = self.factory.get(f"/protected/?token={self.valid_token.token}")
            self.middleware(request)

            handler.assert_not_called()
        finally:
            access_denied.disconnect(handler)
