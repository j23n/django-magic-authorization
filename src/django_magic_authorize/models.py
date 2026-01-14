from django.db import models
import uuid


class AccessToken(models.Model):
    description = models.CharField(max_length=255, null=False, blank=False)
    path = models.CharField(max_length=255, null=False, blank=False)
    token = models.UUIDField(default=uuid.uuid4, null=False, unique=True)

    is_valid = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True, null=False, blank=False)
    times_accessed = models.IntegerField(default=0)
    last_accessed = models.DateTimeField(null=True, blank=True)
