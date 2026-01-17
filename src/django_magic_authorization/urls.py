from django.urls import path, include


def url_protect(url):
    """
    Protect a specific URL. This can be useful if you don't
    want to protect all matching patterns of a URL path.

    Usage:
        from django_magic_authorization.urls import url_protect

        url_protect("/blog/2024/10/a-post-that-shouldnt-be-public")
    """
    pass


def protected_path(route, view, **kwargs):
    """
    Wrap a URL path to require magic token authorization.

    Usage:
        from django_magic_authorization.urls import protected_path

        urlpatterns = [
            protected_path("private/<int:year>/<str:slug>", views.private_view),
        ]
    """
    django_path = path(route, view, **kwargs)
    setattr(django_path, "_django_magic_authorization", True)
    return django_path
