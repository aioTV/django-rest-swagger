from django.conf.urls import url
from rest_framework_swagger.views import SwaggerUIView, Swagger2JSONView


def swagger_views(config_name=None, path_prefix='^'):
    return [
        url(
            path_prefix + r'swagger\.json$',
            Swagger2JSONView.as_view(swagger_config_name=config_name),
            name='django.swagger.2.0.json.view'
        ),
        url(
            path_prefix + r'$',
            SwaggerUIView.as_view(swagger_config_name=config_name),
            name="django.swagger.base.view"
        ),
    ]


urlpatterns = [
    *(swagger_views() + swagger_views(path_prefix=r'^(?P<swagger_config_name>[\w]+)/'))
]
