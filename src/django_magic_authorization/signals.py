from django.dispatch import Signal

# Sent after successful token validation.
# sender=AccessToken, request=request, token=AccessToken instance, path=protected_path
access_granted = Signal()

# Sent when access is denied.
# sender=None, request=request, path=request.path, reason="no_token"|"invalid_token"
access_denied = Signal()
