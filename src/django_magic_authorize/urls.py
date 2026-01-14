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
    
    return(route, view, **kwargs)


def include_protect(arg, namespace=None):
    """
    Wrap a URLResolver to require magic token authorization for all
    included paths.

    Usage:
        from django_magic_authorize import include_protect

        urlpatterns = [
            path("admin/", include_protect("admin.urls")),
        ]
    """
    resolver = include(arg, namespace=namespace)

    resolver._magic_authorize_protected = True

    return resolver
    
