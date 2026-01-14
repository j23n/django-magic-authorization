from django.urls import path, include


def path_protect(route, view, **kwargs):
    """
    Wrap a URL path to require magic token authorization.

    Usage:
        from django_magic_authorize.urls import path_protect

        urlpatterns = [
            path_protect("private/", views.private_view),
        ]
    """
    # Set a special attribute on the view
    view._magic_authorize_protected = True

    return path(route, view, **kwargs)


