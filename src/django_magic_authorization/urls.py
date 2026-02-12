from django.urls import path


def protected_path(route, view, protect_fn=None, **kwargs):
    """
    Wrap a URL path to require magic token authorization.

    Args:
        route:      RoutePattern
        view:       view function or class
        protect_fn: optional callable that is passed captured values of the
                    RequestPattern. Should return True if the path is protected
                    or False if not
    Usage:
        from django_magic_authorization.urls import protected_path

        urlpatterns = [
            protected_path("private/", views.private_view),
            protected_path(
                "<str:visibility>/<int:pk>",
                views.detail_view,
                protect_fn=lambda kwargs: kwargs["visibility"] == "private"
            ),
        ]
    """
    django_path = path(route, view, **kwargs)
    setattr(django_path, "_django_magic_authorization", True)
    setattr(django_path, "_django_magic_authorization_fn", protect_fn)
    return django_path
