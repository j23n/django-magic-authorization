# Django Magic Authorization

Token-based authorization middleware for protecting Django URL paths.

## Installation

```
uv add django-magic-authorization
```

or

```
pip install django-magic-authorization
```

## Setup

Add the app and middleware to your Django settings:

```python
# settings.py
INSTALLED_APPS = [
    ...,
    "django_magic_authorization",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django_magic_authorization.middleware.MagicAuthorizationMiddleware",
    ...,
]
```

Place `MagicAuthorizationMiddleware` after `SecurityMiddleware`.

Run migrations:

```
python manage.py migrate
```

## Quick start

Mark any URL as protected using `protected_path`, a drop-in replacement for
`django.urls.path`:

```python
# urls.py
from django.http import HttpResponse
from django_magic_authorization.urls import protected_path

def secret_view(request):
    return HttpResponse("Secret content")

urlpatterns = [
    protected_path("secret/", secret_view),
]
```

Accessing `/secret/` without a token returns 403. Create a token to grant
access:

```python
from django_magic_authorization.models import AccessToken

token = AccessToken.objects.create(path="secret/", description="Demo token")
print(token.token)
# e.g. "aB3x..."
```

Visit `/secret/?token=aB3x...` to authenticate. The token is stripped from the
URL via redirect, and a cookie is set for subsequent requests.

## Dynamic URL patterns

`protected_path` supports the same route syntax as `django.urls.path`,
including captured parameters:

```python
urlpatterns = [
    protected_path("blog/<int:year>/<str:slug>/", blog_detail_view),
]
```

A token with `path="blog/<int:year>/<str:slug>/"` will protect all URLs
matching that pattern.

## Nested paths with include()

Use `protected_path` with `include()` to protect an entire URL subtree:

```python
from django.urls import include
from django_magic_authorization.urls import protected_path

urlpatterns = [
    protected_path("internal/", include("internal.urls")),
]
```

All paths under `/internal/` are protected with a single token.

## Conditional protection (protect_fn)

Pass a `protect_fn` callable to protect URLs conditionally based on captured
parameters. It receives the captured kwargs dict and should return `True` if the
path should be protected:

```python
urlpatterns = [
    protected_path(
        "<str:visibility>/<int:pk>/",
        detail_view,
        protect_fn=lambda kwargs: kwargs["visibility"] == "private",
    ),
]
```

Here `/private/42/` requires a token, but `/public/42/` does not.

## Token management

### Creation

```python
from django_magic_authorization.models import AccessToken

token = AccessToken.objects.create(
    path="secret/",
    description="For reviewers",
)
```

Tokens are generated using `secrets.token_urlsafe(32)`.

### Revocation

```python
token.is_valid = False
token.save()
```

### Expiration

```python
from django.utils import timezone
from datetime import timedelta

AccessToken.objects.create(
    path="secret/",
    description="Expires in 7 days",
    expires_at=timezone.now() + timedelta(days=7),
)
```

### Usage limits

```python
AccessToken.objects.create(
    path="secret/",
    description="Single use",
    max_uses=1,
)
```

### Access stats

Each token tracks `times_accessed` and `last_accessed` automatically.

### Cleanup command

Remove expired and exhausted tokens:

```
python manage.py cleanup_expired_tokens
```

## Cookie behavior

On first valid token access, a cookie is set so subsequent requests to the same
path do not require the token in the URL. Cookies are scoped to the static
prefix of the protected path pattern (everything before the first dynamic
segment). Cookie attributes are configurable via settings.

## Custom 403 responses

Override the default 403 response with a template or a handler function.

**Template:**

```python
MAGIC_AUTHORIZATION = {
    "FORBIDDEN_TEMPLATE": "errors/403.html",
}
```

The template receives `path` in its context.

**Handler function:**

```python
MAGIC_AUTHORIZATION = {
    "FORBIDDEN_HANDLER": "myapp.views.custom_forbidden",
}
```

The handler is called as `handler(request, path)` and must return an
`HttpResponse`.

## Signals

Two signals are available for monitoring access:

**access_granted** -- sent after successful token validation.

```python
from django_magic_authorization.signals import access_granted

def on_access_granted(sender, request, token, path, **kwargs):
    ...

access_granted.connect(on_access_granted)
```

Keyword arguments: `sender` (AccessToken class), `request`, `token`
(AccessToken instance), `path`.

**access_denied** -- sent when access is denied.

```python
from django_magic_authorization.signals import access_denied

def on_access_denied(sender, request, path, reason, **kwargs):
    ...

access_denied.connect(on_access_denied)
```

Keyword arguments: `sender` (None), `request`, `path`, `reason`
(`"no_token"` or `"invalid_token"`).

## Admin interface

Register the app to get a management interface for access tokens. The admin
displays all token fields, provides a dropdown of registered protected paths
when creating tokens, and shows a computed access link for each token. Tokens
with paths that no longer match a registered route are flagged in the list view.

## Settings

All settings are namespaced under `MAGIC_AUTHORIZATION` in your Django settings:

```python
MAGIC_AUTHORIZATION = {
    "COOKIE_SECURE": True,
    "COOKIE_MAX_AGE": 86400,
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `COOKIE_SECURE` | `not DEBUG` | Set the `Secure` flag on auth cookies |
| `COOKIE_MAX_AGE` | `31536000` (1 year) | Cookie max age in seconds |
| `COOKIE_SAMESITE` | `"lax"` | Cookie `SameSite` attribute |
| `COOKIE_HTTPONLY` | `True` | Set the `HttpOnly` flag on auth cookies |
| `COOKIE_PREFIX` | `"django_magic_authorization_"` | Prefix for cookie names |
| `TOKEN_PARAM` | `"token"` | Query parameter name for the token |
| `FORBIDDEN_TEMPLATE` | `None` | Template path for custom 403 page |
| `FORBIDDEN_HANDLER` | `None` | Dotted path to a custom 403 handler function |

## Security

- Use HTTPS in production. `COOKIE_SECURE` defaults to `True` when `DEBUG` is
  `False`.
- Tokens are automatically stripped from URLs via redirect after first use,
  preventing token leakage in browser history and referrer headers.
- Auth cookies are `HttpOnly` and `SameSite=lax` by default.
- Tokens are generated with `secrets.token_urlsafe(32)` (256 bits of entropy).
