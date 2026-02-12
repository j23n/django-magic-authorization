from django.db import models
import secrets


class AccessToken(models.Model):
    def gen_token():
        return secrets.token_urlsafe(32)

    description = models.CharField(max_length=255, null=False, blank=False)
    path = models.CharField(max_length=255, null=False, blank=False)
    token = models.CharField(max_length=64, default=gen_token, null=False, unique=True)

    is_valid = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True, null=False, blank=False)
    times_accessed = models.IntegerField(default=0)
    last_accessed = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.description} ({self.path})"

    def __repr__(self):
        return f"<AccessToken: {self.description} ({self.path})>"

