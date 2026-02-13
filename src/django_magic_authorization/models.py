from django.db import models
import secrets


def _gen_token():
    return secrets.token_urlsafe(32)


class AccessToken(models.Model):
    """A token that grants access to a protected URL path.

    Tokens are generated automatically using ``secrets.token_urlsafe(32)``.
    They can be constrained by expiration time (``expires_at``) and usage
    count (``max_uses``), and revoked by setting ``is_valid`` to ``False``.
    """

    description = models.CharField(max_length=255, null=False, blank=False)
    path = models.CharField(max_length=255, null=False, blank=False)
    token = models.CharField(max_length=64, default=_gen_token, null=False, unique=True)

    is_valid = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    max_uses = models.PositiveIntegerField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, null=False, blank=False)
    times_accessed = models.IntegerField(default=0)
    last_accessed = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.description} ({self.path})"

    def __repr__(self):
        return f"<AccessToken: {self.description} ({self.path})>"

