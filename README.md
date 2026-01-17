# Django Magic Authorize

This middleware adds simple token-based authorization for private content to any Django project.

## Installation

First, install the package using your favorite python package manager

`uv add django-magic-authorization`

or

`pip install django-magic-authorization`

Second, you need to enable the app in your Django project.

```python
# settings.py
INSTALLED_APPS = [
  ...
  "django_magic_authorization"
  ...
]

MIDDLEWARE = [
  ...
  "django_magic_authorization.middleware.MagicAuthorizeMiddleware",
  ...
]

```

Third, run the migrations to add the relevant schemas to your database

```
python manage.py migrate
```

## Quickstart

Authorization happens on the URL level. The package offers a drop-in replacement for `django.urls.path`, that is used to mark urls as protected. You can use this in conjunction with `include()` to protect sub-paths quickly.

```python
# urls.py
from django.urls import path, include
from django.http import HttpResponse
from django_magic_authorization.urls import protected_path


def test_view(request):
  return HttpResponse("Hello")

urlpatterns = [
  path("unprotected", test_view),
  protected_path("protected", test_view)
]
```

With a running development server

```bash
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/protected
403
```

This URL can now only be accessed by someone with a valid token.

There is a django admin interface for you to create, manage and delete access tokens for these protected paths. You can also do so in the shell.

```ipython
>>> t = AccessToken.objects.create(path="protected", description="Test token creation")
>>> t.token
your-token-value
```

using this token to access the protected view:

```bash
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/protected?token=your-token-value
200
```

