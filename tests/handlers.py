from django.http import JsonResponse


def json_forbidden(request, path):
    return JsonResponse({"error": "forbidden", "path": path}, status=403)
