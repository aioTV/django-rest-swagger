# -*- coding: utf-8 -*-
from django.conf import settings
from .constants import DEFAULT_PAGE_DEFINITION


class SwaggerConfig(object):
    DEFAULT_SWAGGER_SETTINGS = {
        'exclude_url_names': [],
        'exclude_namespaces': [],
        'exclude_module_paths': [],
        'exclude_url_patterns': [],
        'include_module_paths': [],
        'is_authenticated': False,
        'is_superuser': False,
        'base_path': '',
        'tag_matchers': ['rest_framework_swagger.utils.tag_from_prefix'],
        'default_page_definition': DEFAULT_PAGE_DEFINITION,
    }

    def __init__(self):
        super(SwaggerConfig, self).__init__()
        self.global_settings = self.DEFAULT_SWAGGER_SETTINGS.copy()
        self.global_settings.update(getattr(settings, 'SWAGGER_GLOBAL_SETTINGS', {}))

    def get_config(self, config_name=None):
        config_name = config_name or "default"
        if not hasattr(settings, 'SWAGGER_LOCAL_SETTINGS'):
            raise Exception("SWAGGER_LOCAL_SETTINGS not configured in settings")
        if config_name not in settings.SWAGGER_LOCAL_SETTINGS:
            raise Exception("{} swagger settings not defined in SWAGGER_LOCAL_SETTINGS".format(config_name))

        current_config = self.global_settings.copy()
        current_config.update(settings.SWAGGER_LOCAL_SETTINGS[config_name])
        return current_config
