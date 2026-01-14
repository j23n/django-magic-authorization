from django.http.response import HttpResponseForbidden
from django.db.models import F
from django.utils import timezone
from django_magic_authorize.models import AccessToken


class MagicAuthRouter(object):
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "_registry"):
            self._registry = set()

    def register(self, path):
        if not path.startswith("/"):
            path = "/" + path
        self._registry.add(path)


class MagicAuthMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        reg = MagicAuthRouter()._registry

        protected_path = None
        for path in reg:
            if request.path.startswith(path):
                protected_path = path
                break

        if not protected_path:
            return self.get_response(request)

        if (user_token := request.GET.get("token")) is None:
            return HttpResponseForbidden()

        if not (
            db_token := AccessToken.objects.filter(
                token=user_token, is_valid=True, path=protected_path
            )
        ).exists():
            return HttpResponseForbidden()

        db_token.update(
            last_accessed=timezone.now(), times_accessed=F("times_accessed") + 1
        )
        return self.get_response(request)
