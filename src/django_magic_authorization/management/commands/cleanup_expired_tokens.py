from django.core.management.base import BaseCommand
from django.db.models import F, Q
from django.utils import timezone

from django_magic_authorization.models import AccessToken


class Command(BaseCommand):
    help = "Delete expired and exhausted access tokens"

    def handle(self, *args, **options):
        now = timezone.now()
        expired = AccessToken.objects.filter(
            Q(expires_at__isnull=False, expires_at__lte=now)
            | Q(max_uses__isnull=False, max_uses__lte=F("times_accessed"))
        )
        count = expired.count()
        expired.delete()
        self.stdout.write(f"Deleted {count} expired/exhausted token(s).")
