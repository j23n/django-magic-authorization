from django.apps import AppConfig


class DjangoMagicAuthorizeConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_magic_authorize"

    def ready(self):
        # discover all protected URL paths after initialization
        from django_magic_authorize.middleware import discover_protected_paths
        discover_protected_paths()
