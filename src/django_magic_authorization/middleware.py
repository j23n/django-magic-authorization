import logging
from urllib.parse import quote

from django.http.response import HttpResponseForbidden, HttpResponseRedirect
from django.db.models import F, Q
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.module_loading import import_string
from django.urls import get_resolver
from django.urls.resolvers import RoutePattern
from django_magic_authorization.models import AccessToken
from django_magic_authorization.settings import get_setting
from django_magic_authorization.signals import access_denied, access_granted

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

    def _deny(self, request, reason):
        access_denied.send(
            sender=None, request=request, path=request.path, reason=reason
        )

        handler_path = get_setting("FORBIDDEN_HANDLER")
        if handler_path:
            handler = import_string(handler_path)
            return handler(request, request.path)

        template_name = get_setting("FORBIDDEN_TEMPLATE")
        if template_name:
            content = render_to_string(
                template_name, {"path": request.path}, request=request
            )
            return HttpResponseForbidden(content)

        messages = {
            "no_token": "Access denied: No token provided",
            "invalid_token": "Access denied: Invalid token",
        }
        return HttpResponseForbidden(messages.get(reason, "Access denied"))

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

        cookie_key = f"{get_setting('COOKIE_PREFIX')}{quote(protected_path, safe='')}"

        token_param = get_setting("TOKEN_PARAM")
        query_token = request.GET.get(token_param)
        user_token = query_token or request.COOKIES.get(cookie_key)
        if user_token is None:
            logger.info(f"Access denied to {request.path}: no token provided")
            return self._deny(request, "no_token")

        # Token validation
        now = timezone.now()
        if not (
            db_token := AccessToken.objects.filter(
                token=user_token, is_valid=True, path=protected_path
            )
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
            .filter(Q(max_uses__isnull=True) | Q(max_uses__gt=F("times_accessed")))
        ).exists():
            logger.info(f"Access denied to {request.path}: invalid token provided")
            return self._deny(request, "invalid_token")

        # Update token stats
        db_token.update(
            last_accessed=timezone.now(), times_accessed=F("times_accessed") + 1
        )

        access_granted.send(
            sender=AccessToken,
            request=request,
            token=db_token.first(),
            path=protected_path,
        )

        if query_token:
            # Redirect to strip the token from the URL
            query_dict = request.GET.copy()
            query_dict.pop(token_param)
            redirect_url = request.path
            if query_dict:
                redirect_url += "?" + query_dict.urlencode()
            response = HttpResponseRedirect(redirect_url)
        else:
            response = self.get_response(request)

        # Scope cookie path to the static prefix of the protected pattern
        dynamic_idx = protected_path.find("<")
        if dynamic_idx == -1:
            cookie_path = "/" + protected_path
        else:
            cookie_path = "/" + protected_path[:dynamic_idx]

        # Set the cookie for future auth
        response.set_cookie(
            key=cookie_key,
            value=user_token,
            path=cookie_path,
            max_age=get_setting("COOKIE_MAX_AGE"),
            httponly=get_setting("COOKIE_HTTPONLY"),
            secure=get_setting("COOKIE_SECURE"),
            samesite=get_setting("COOKIE_SAMESITE"),
        )

        logger.debug(f"Access granted to {protected_path}")
        return response
