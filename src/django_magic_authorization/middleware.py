import logging
from urllib.parse import quote

from django.http.response import HttpResponseForbidden
from django.db.models import F
from django.utils import timezone
from django.urls import get_resolver
from django.urls.resolvers import RoutePattern
from django_magic_authorization.models import AccessToken

logger = logging.getLogger(__name__)


class MagicAuthorizationRouter:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # __init__ is called, even using the singleton pattern
        if not hasattr(self, "_registry"):
            self._registry = set()

    def register(self, prefix: str, pattern: RoutePattern, protect_fn=None):
        self._registry.add((prefix, pattern, protect_fn))

    def get_protected_paths(self):
        return [prefix + str(pattern) for prefix, pattern, _ in self._registry]

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
                if hasattr(upattern, "_django_magic_authorization"):
                    # register prefix - all paths under it are protected
                    self.register(
                        prefix,
                        upattern.pattern,
                        upattern._django_magic_authorization_fn,
                    )
                else:
                    # recurse into the URLResolver to find protected
                    # URLPatterns
                    new_prefix = prefix + str(upattern.pattern)
                    self.walk_patterns(upattern.url_patterns, new_prefix)
            # handle URLPatterns
            elif hasattr(upattern, "_django_magic_authorization"):
                self.register(
                    prefix, upattern.pattern, upattern._django_magic_authorization_fn
                )
        logger.debug(f"Parsed protected paths {self.get_protected_paths()}")


def discover_protected_paths():
    router = MagicAuthorizationRouter()
    resolver = get_resolver()
    router.walk_patterns(resolver.url_patterns)


class MagicAuthorizationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        reg = MagicAuthorizationRouter()._registry

        # determine if this is a protected path
        protected_path = None
        for prefix, pattern, protect_fn in reg:
            path_without_prefix = request.path.lstrip("/").removeprefix(prefix)
            match = pattern.match(path_without_prefix)

            if match:
                remaining_path, args, kwargs = match

                if not str(pattern).endswith("/"):
                    if remaining_path and not remaining_path.startswith("/"):
                        continue

                # check custom protect function matched values
                if protect_fn:
                    try:
                        if not protect_fn(kwargs):
                            continue
                    except Exception as e:
                        logger.error(
                            f"Error evaluating protect function for path {request.path}: {e}"
                        )
                        # Fail safe: treat path as protected

                protected_path = prefix + str(pattern)
                break

        if not protected_path:
            logger.debug(f"Access granted to {request.path}: not a protected path")
            return self.get_response(request)

        cookie_key = f"django_magic_authorization_{quote(protected_path, safe='')}"

        user_token = request.GET.get("token") or request.COOKIES.get(cookie_key)
        if user_token is None:
            logger.info(f"Access denied to {request.path}: no token provided")
            return HttpResponseForbidden("Access denied: No token provided")

        # Token validation
        if not (
            db_token := AccessToken.objects.filter(
                token=user_token, is_valid=True, path=protected_path
            )
        ).exists():
            logger.info(f"Access denied to {request.path}: invalid token provided")
            return HttpResponseForbidden("Access denied: Invalid token")

        # Update token stats
        db_token.update(
            last_accessed=timezone.now(), times_accessed=F("times_accessed") + 1
        )

        # Set the cookie for future auth
        response = self.get_response(request)
        response.set_cookie(
            key=cookie_key,
            value=user_token,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            secure=True,
            samesite="lax",
        )

        logger.debug(f"Access granted to {protected_path}")
        return response
