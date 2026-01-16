import uuid
import logging

from django.http.response import HttpResponseForbidden
from django.db.models import F
from django.utils import timezone
from django.urls import get_resolver
from django.urls.resolvers import RoutePattern
from django_magic_authorize.models import AccessToken


logger = logging.getLogger(__name__)


class MagicAuthRouter(object):
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # __init__ is called, even using the singleton pattern
        if not hasattr(self, "_registry"):
            self._registry = set()

    def register(self, prefix: str, pattern: RoutePattern):
        self._registry.add((prefix, pattern))

    def get_protected_paths(self):
        return [prefix + str(pattern) for prefix, pattern in self._registry]

    def walk_patterns(self, url_patterns, prefix=""):
        """
        Walk the URLPatterns and URLResolvers from django.urls.get_resolver.url_patterns.

        There are two "patterns" to deal with here. The first is the URLPattern,
        the other the RoutePattern. The latter is the url string: "/home" or
        "/blog/<int:year>/<str:slug>". It is contained within the first, which also
        includes the view and possibly a namespace."
        """
        for upattern in url_patterns:
            # check if we're dealing with a URLResolver
            if hasattr(upattern, "url_patterns"):
                if hasattr(upattern, "_django_magic_authorize"):
                    # register prefix - all paths under it are protected
                    self.register(prefix, upattern.pattern)
                else:
                    # recurse into the URLResolver to find protected
                    # URLPatterns
                    new_prefix = prefix + str(upattern.pattern)
                    self.walk_patterns(upattern.url_patterns, new_prefix)
            # handle URLPatterns
            if hasattr(upattern, "_django_magic_authorize"):
                self.register(prefix, upattern.pattern)


def discover_protected_paths():
    router = MagicAuthRouter()
    resolver = get_resolver()
    router.walk_patterns(resolver.url_patterns)


class MagicAuthMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        reg = MagicAuthRouter()._registry

        protected_path = None
        for prefix, pattern in reg:
            path_without_prefix = request.path.removeprefix(prefix).lstrip("/")
            match = pattern.match(path_without_prefix)

            # determine if this is a protected path, with boundary checking
            # e.g. handle "/admin" vs "/admin-something"
            if match:
                remaining_path, _, _ = match

                if not str(pattern).endswith("/"):
                    if remaining_path and not remaining_path.startswith("/"):
                        continue

                protected_path = prefix + str(pattern)
                break

        if not protected_path:
            return self.get_response(request)

        if (user_token := request.GET.get("token")) is None:
            logger.warning(f"Access denied to {path}: no token provided")
            return HttpResponseForbidden("Access denied: No token provided")

        try:
            uuid_token = uuid.UUID(user_token)
        except ValueError:
            logger.warning(f"Access denied to {path}: invalid token")
            return HttpResponseForbidden("Access denied: Invalid token")

        if not (
            db_token := AccessToken.objects.filter(
                token=uuid_token, is_valid=True, path=protected_path
            )
        ).exists():
            logger.warning(f"Access denied to {path}: invalid token")
            return HttpResponseForbidden("Access denied: Invalid token")

        db_token.update(
            last_accessed=timezone.now(), times_accessed=F("times_accessed") + 1
        )
        return self.get_response(request)
