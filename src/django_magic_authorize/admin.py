from django.contrib import admin
from django import forms

from django_magic_authorize.models import AccessToken
from django_magic_authorize.middleware import MagicAuthRouter


class AccessTokenForm(forms.ModelForm):
    def get_routes():
        router = MagicAuthRouter()
        return ((p, p) for p in router.get_protected_paths())

    path_choice = forms.ChoiceField(choices=get_routes)

    def save(self, commit=True):
        path_choice = self.cleaned_data.pop("path_choice")
        self.cleaned_data["path"] = path_choice
        return super().save(commit=commit)

    class Meta:
        model = AccessToken
        exclude = ["path"]


class AccessTokenAdmin(admin.ModelAdmin):
    date_hierarchy = "created_at"
    list_display = (
        "description",
        "display_path",
        "is_valid",
        "get_access_link",
        "created_at",
        "last_accessed",
        "times_accessed",
    )
    readonly_fields = (
        "created_at",
        "last_accessed",
        "times_accessed",
        "token",
        "get_access_link",
    )
    form = AccessTokenForm

    def display_path(self, obj):
        router = MagicAuthRouter()
        if obj.path not in router.get_protected_paths():
            return f"❗ {obj.path}"
        else:
            return obj.path

    def get_access_link(self, obj):
        return f"{obj.path}?token={obj.token}"
    get_access_link.short_description = "Access Link"


admin.site.register(AccessToken, AccessTokenAdmin)
