import json

from django.conf import settings
from django.views.generic import View
from django.utils.safestring import mark_safe
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.core.exceptions import PermissionDenied
from .config import SwaggerConfig

from rest_framework.views import Response, APIView
from rest_framework.settings import api_settings
from rest_framework.permissions import AllowAny

import rest_framework_swagger as rfs
from rest_framework_swagger.urlparser import UrlParser
from rest_framework_swagger.docgenerator import DocumentationGenerator

try:
    JSONRenderer = list(filter(
        lambda item: item.format == 'json',
        api_settings.DEFAULT_RENDERER_CLASSES,
    ))[0]
except IndexError:
    from rest_framework.renderers import JSONRenderer


class BaseSwaggerView(object):
    swagger_config_name = None

    def check_permission(self, request, swagger_config_name):
        self.config = SwaggerConfig().get_config(swagger_config_name or self.swagger_config_name)
        if not self.has_permission(request):
            raise PermissionDenied()

    def has_permission(self, request):
        if self.config['is_superuser'] and not request.user.is_superuser:
            return False
        if self.config['is_authenticated'] and not request.user.is_authenticated():
            return False
        return True


class SwaggerUIView(BaseSwaggerView, View):
    def get(self, request, version=None, swagger_config_name=None):
        self.check_permission(request, swagger_config_name)
        auth_token = getattr(request.user, 'auth_token', None)
        data = {
            'swagger_settings': {
                'swagger_file': self.get_json_url(request),
                'api_version': rfs.SWAGGER_SETTINGS.get('api_version', ''),
                'user_token': auth_token.key if auth_token else '',
                'config': self.config,
            },
            'rest_framework_settings': {
                'DEFAULT_VERSIONING_CLASS':
                    settings.REST_FRAMEWORK.get('DEFAULT_VERSIONING_CLASS', '')
                    if hasattr(settings, 'REST_FRAMEWORK') else None,

            },
            'django_settings': {
                'CSRF_COOKIE_NAME': mark_safe(
                    json.dumps(getattr(settings, 'CSRF_COOKIE_NAME', 'csrftoken'))),
            }
        }
        response = render_to_response(
            "rest_framework_swagger/index.html", RequestContext(request, data))

        return response

    def get_json_url(self, request):
        json_path = self.config.get("json_path", None)
        if not json_path:
            json_path = request.path.rstrip("/") + "/swagger.json"
        return request.build_absolute_uri(json_path)


class Swagger2JSONView(BaseSwaggerView, APIView):
    permission_classes = (AllowAny,)
    renderer_classes = (JSONRenderer, )

    def get(self, request, *args, version=None, swagger_config_name=None, **kwargs):
        self.check_permission(request, swagger_config_name)
        paths = self.get_paths()
        generator = DocumentationGenerator(
            for_user=request.user,
            config=self.config,
            request=request
        )
        return Response(generator.get_root(paths))

    def get_paths(self):
        urlparser = UrlParser(self.config, self.request)
        return urlparser.get_apis()
