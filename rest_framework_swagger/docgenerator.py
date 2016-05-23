"""Generates API documentation by introspection."""
from django.contrib.auth.models import AnonymousUser
from django.utils.module_loading import import_string
import rest_framework

from rest_framework import viewsets, mixins
from rest_framework.generics import GenericAPIView

from rest_framework.serializers import BaseSerializer

from .introspectors import (
    APIViewIntrospector,
    GenericViewIntrospector,
    BaseMethodIntrospector,
    ViewSetIntrospector,
    WrappedAPIViewIntrospector,
    extract_serializer_fields,
)
from .compat import OrderedDict
from .utils import get_serializer_name, template_dict, find_refs, find_used_refs, get_child


class DocumentationGenerator(object):
    def __init__(self, for_user=None, config=None, request=None):
        self.config = config
        self.user = for_user or AnonymousUser()
        self.request = request
        self._tag_matchers = list(map(import_string, self.config.get('tag_matchers')))
        self._operation_filters = list(map(import_string, self.config.get('operation_filters', [])))
        # Serializers defined in docstrings
        self.body_serializers = set()
        # Serializers defined in fields
        self.fields_serializers = set()
        # Response classes defined in docstrings
        self.explicit_response_types = dict()


    def get_root(self, endpoints_conf):
        self.default_payload_definition_name = self.config.get('default_payload_definition_name', None)
        self.default_payload_definition = self.config.get('default_payload_definition', None)
        if self.default_payload_definition:
            self.explicit_response_types.update({
                self.default_payload_definition_name: self.default_payload_definition
            })
        root = OrderedDict([
            ('swagger', '2.0'),
            ('info', self.config.get('info', {
                'contact': {},
                'title': 'API Documentation',
                'version': self.request.version,
                'description': '',
            })),
            ('basePath', self.config.get('base_path', '')),
            ('host', self.config.get('host', self.request.get_host())),
            ('schemes', self.config.get('schemes', ['https' if self.request.is_secure() else 'http'])),
            ('securityDefinitions', self.config.get('securityDefinitions', {})),
            ('tags', self.config.get('tags', [])),
            ('paths', self.get_paths(endpoints_conf)),
            ('definitions', self.get_definitions(endpoints_conf)),
        ])

        # Remove unreferenced items..
        used_refs = find_used_refs(find_refs(root['paths']), root['definitions'])
        for unused_ref in set(root['definitions']) - used_refs:
            del root['definitions'][unused_ref]

        return root

    def get_paths(self, endpoints_conf):
        paths_dict = {}
        base_path = self.config.get('base_path')
        for endpoint in endpoints_conf:
            # Can't have paths above the base path in the spec
            if base_path and not endpoint['path'].startswith(base_path):
                continue
            endpoint['path'] = endpoint['path'][len(base_path):]
            path_item = self.get_path_item(endpoint)
            if path_item:
                paths_dict[endpoint['path']] = path_item
        paths_dict = OrderedDict(sorted(paths_dict.items()))
        return paths_dict

    def get_path_item(self, api_endpoint):
        introspector = self.get_introspector(api_endpoint)

        path_item = {}

        for operation in self.get_operations(api_endpoint, introspector):
            path_item[operation.pop('method').lower()] = operation

        # No operations for this path
        if not path_item:
            return path_item

        method_introspectors = self.get_method_introspectors(api_endpoint, introspector)
        # we get the main parameters (common to all operations) from the first view operation
        # only path parameters are common to all operations
        path_item['parameters'] = method_introspectors[0].build_path_parameters()

        return path_item

    def get_method_introspectors(self, api_endpoint, introspector):
        return [method_introspector for method_introspector in introspector if
                isinstance(method_introspector, BaseMethodIntrospector)
                and not method_introspector.get_http_method() == 'OPTIONS']

    def get_tags(self, url_path):
        tags = []
        for matcher in self._tag_matchers:
            tags.extend(matcher(url_path, self.config))
        return tags

    def get_operations(self, api_endpoint, introspector):
        """
        Returns docs for the allowed methods of an API endpoint
        """
        operations = []

        for method_introspector in self.get_method_introspectors(api_endpoint, introspector):
            doc_parser = method_introspector.yaml_parser

            if doc_parser.should_omit_endpoint():
                continue

            serializer = self._get_method_serializer(method_introspector)

            response_type = self._get_method_response_type(
                doc_parser, serializer, introspector, method_introspector)

            if doc_parser.get_param('paginated', (method_introspector.method == 'list')):
                response_type = self._paginate_response_type(response_type, method_introspector)

            operation_method = method_introspector.get_http_method()

            produces = method_introspector.get_produces()
            produces = doc_parser.get_param(param_name='produces', default=produces or self.config.get('produces'))

            consumes = method_introspector.get_consumes()
            consumes = doc_parser.get_param(param_name='consumes', default=consumes or self.config.get('consumes'))

            operation = {
                'method': operation_method,
                'description': method_introspector.get_description(),
                'summary': method_introspector.get_summary(),
                'operationId': method_introspector.get_operation_id(),
                'produces': produces,
                'consumes': consumes,
                'tags': doc_parser.get_param(param_name='tags', default=self.get_tags(api_endpoint['path'])),
                'parameters': self._get_operation_parameters(method_introspector, operation_method, consumes)
            }
            operation.update(doc_parser.get_operation_extensions())

            if doc_parser.yaml_error is not None:
                operation['description'] += '\n\n<pre>YAMLError:\n {err}</pre>'.format(
                    err=doc_parser.yaml_error)

            response_messages = {}
            # set default response reference
            if self.default_payload_definition:
                response_messages['default'] = {
                    'schema': {
                        '$ref': '#/definitions/{}'.format(self.default_payload_definition_name)
                    }
                }

            response_code, response_obj = self._get_default_response_object(operation_method, response_type)
            response_messages[response_code] = response_obj

            # overwrite default and add more responses from docstrings
            response_messages.update(doc_parser.get_response_messages())

            # Remove blank response objects - allows yaml to remove default responses
            for code in list(response_messages):
                if not response_messages[code]:
                    del response_messages[code]

            operation['responses'] = response_messages
            for filter_ in self._operation_filters:
                filter_(operation, callback=method_introspector.callback, method=method_introspector.method)
                if not operation:
                    break

            if operation:
                operations.append(operation)

        return operations

    def _get_default_response_object(self, operation_method, response_type):
        if response_type == 'object':
            schema = {'type': 'object'}
        else:
            schema = {'$ref': '#/definitions/' + response_type}

        if operation_method == 'DELETE':
            return '204', {
                'description': 'Successfully deleted',
            }
        if operation_method == 'POST':
            return '201', {
                'description': 'Successfully created',
                'schema': schema,
            }

        return '200', {
            'description': 'Successful operation',
            'schema': schema,
        }

    def _paginate_response_type(self, response_type, method_introspector):
        doc_parser = method_introspector.yaml_parser
        definition_name = response_type + 'Page'

        if response_type == 'object':
            replacement = ('type', 'object')
        else:
            replacement = ('$ref', '#/definitions/{}'.format(response_type))

        page_definition = doc_parser.get_param('page_definition', self.config.get('default_page_definition'))
        page_definition = template_dict(page_definition, ('$ref', '#/definitions/*'), replacement)

        self.explicit_response_types[definition_name] = page_definition
        return definition_name

    def _get_operation_parameters(self, introspector, method, consumes):
        """
        :param introspector: method introspector
        :return : if the serializer must be placed in the body, it will build
        the body parameters and add the serializer to the body_serializers list
        else it will discover the parameters (from docstring and serializer)
        """
        serializer = introspector.get_request_serializer_class()
        parameters = []
        if serializer:
            if set(consumes).issubset({'multipart/form-data', 'application/x-www-form-encoded'}):
                parameters.extend(introspector.get_form_parameters())
            elif getattr(getattr(serializer, 'Meta', None), '_in', 'body') == 'body':
                self.body_serializers.add(serializer)
                parameters.append(introspector.build_body_parameters())

        parameters.extend(
            introspector.yaml_parser.discover_parameters(inspector=introspector)
        )
        return parameters

    def get_introspector(self, api):
        path = api['path']
        pattern = api['pattern']
        callback = api['callback']
        if callback.__module__ == 'rest_framework.decorators':
            return WrappedAPIViewIntrospector(callback, path, pattern, self.user)
        elif issubclass(callback, viewsets.ViewSetMixin):
            patterns = [api['pattern']]
            return ViewSetIntrospector(callback, path, pattern, self.user, patterns=patterns)
        elif issubclass(callback, GenericAPIView) and self._callback_generic_is_implemented(callback):
            return GenericViewIntrospector(callback, path, pattern, self.user)
        else:
            return APIViewIntrospector(callback, path, pattern, self.user)

    def _callback_generic_is_implemented(self, callback):
        """
        An implemented callback is a view that extends from one of the GenericApiView child.
        Because some views might extend directly from GenericAPIView without
        implementing one of the List, Create, Retrieve, etc. mixins
        """
        return (issubclass(callback, mixins.CreateModelMixin) or
                issubclass(callback, mixins.ListModelMixin) or
                issubclass(callback, mixins.RetrieveModelMixin) or
                issubclass(callback, mixins.UpdateModelMixin) or
                issubclass(callback, mixins.DestroyModelMixin))

    def get_definitions(self, endpoints_conf):
        """
        Builds a list of Swagger 'models'. These represent
        DRF serializers and their fields
        """
        serializers = self._get_serializer_set(endpoints_conf)
        serializers.update(self._find_field_serializers(serializers))

        models = {}

        def add_serializer_tree(serializer, write):
            serializer_name = get_serializer_name(serializer, write=write)
            if serializer_name in models:
                return

            child_serializer = get_child(serializer)
            if child_serializer:
                add_serializer_tree(child_serializer, write)

            models[serializer_name] = self.get_definition(serializer, write)

        for serializer in serializers:
            add_serializer_tree(serializer, write=False)
        for serializer in self.body_serializers:
            add_serializer_tree(serializer, write=True)

        models.update(self.explicit_response_types)
        models.update(self.fields_serializers)
        return models

    def get_definition(self, serializer, write=False):
        """
        :param serializer: Serializer to describe
        :type serializer: serializer instance
        """
        child = get_child(serializer)
        if child and serializer.many:
            child_name = get_serializer_name(child, write=write)
            if child_name not in self.explicit_response_types:
                self.explicit_response_types[child_name] = self.get_definition(child, write=write)

            return {
                'type': 'array',
                'items': {
                    '$ref': '#/definitions/{}'.format(child_name)
                }
            }

        data = self._get_serializer_fields(serializer)
        serializer_type = 'object'
        fields_to_skip = set(data['read_only'] if write else data['write_only'])
        properties = OrderedDict((k, v) for k, v in list(data['fields'].items())
                                 if k not in fields_to_skip)

        definition = {
            'properties': properties,
            'type': serializer_type
        }
        required_properties = [i for i in list(properties.keys()) if i in data.get('required', [])]
        if required_properties:
            definition['required'] = required_properties

        return definition

    def _get_serializer_set(self, endpoints_conf):
        """
        Returns a set of serializer classes for a provided list
        of APIs
        """
        serializers = set()

        for endpoint in endpoints_conf:
            introspector = self.get_introspector(endpoint)
            for method_introspector in introspector:
                serializer = self._get_method_serializer(method_introspector)
                if serializer is not None:
                    serializers.add(serializer)
                extras = method_introspector.get_extra_serializer_classes()
                for extra in extras:
                    if extra is not None:
                        serializers.add(extra)

        return serializers

#################################################

    def _get_method_serializer(self, method_inspector):
        """
        Returns serializer used in method.
        Registers custom serializer from docstring in scope.

        Serializer might be ignored if explicitly told in docstring
        """
        serializer = method_inspector.get_response_serializer_class()
        doc_parser = method_inspector.yaml_parser

        if doc_parser.get_response_type() is not None:
            # Custom response class detected
            return None

        if doc_parser.should_omit_serializer():
            serializer = None

        return serializer

    def _get_method_response_type(self, doc_parser, serializer,
                                  view_inspector, method_inspector):
        """
        Returns response type for method.
        This might be custom `type` from docstring or discovered
        serializer class name.

        Once custom `type` found in docstring - it'd be
        registered in a scope
        """
        response_type = doc_parser.get_response_type()
        if response_type is not None:
            # Register class in scope
            view_name = view_inspector.callback.__name__
            view_name = view_name.replace('ViewSet', '')
            view_name = view_name.replace('APIView', '')
            view_name = view_name.replace('View', '')
            response_type_name = '{view}{method}Response'.format(
                view=view_name,
                method=method_inspector.method.title().replace('_', '')
            )
            self.explicit_response_types.update({
                response_type_name: {
                    'id': response_type_name,
                    'properties': response_type
                }
            })
            return response_type_name
        else:
            serializer_name = get_serializer_name(serializer)
            if serializer_name is not None:
                return serializer_name

            return 'object'

    def _find_field_serializers(self, serializers, found_serializers=set()):
        """
        Returns set of serializers discovered from fields
        """
        def get_thing(field, key):
            if rest_framework.VERSION >= '3.0.0':
                from rest_framework.serializers import ListSerializer
                if isinstance(field, ListSerializer):
                    return key(field.child)
            return key(field)

        serializers_set = set()
        for serializer in serializers:
            fields = serializer().get_fields()
            for name, field in list(fields.items()):
                if isinstance(field, BaseSerializer):
                    serializers_set.add(get_thing(field, lambda f: f))
                    if field not in found_serializers:
                        serializers_set.update(
                            self._find_field_serializers(
                                (get_thing(field, lambda f: f.__class__),),
                                serializers_set))

        return serializers_set

    def _get_serializer_fields(self, serializer):
        """
        Returns serializer fields in the Swagger MODEL format
        """
        if serializer is None:
            return

        data = OrderedDict({
            'fields': OrderedDict(),
            'required': [],
            'write_only': [],
            'read_only': [],
        })
        for field_data in extract_serializer_fields(serializer):
            name = field_data['name']
            if field_data['write_only']:
                data['write_only'].append(name)
            if field_data['read_only']:
                data['read_only'].append(name)
            if field_data['required']:
                data['required'].append(name)

            f = {}
            data_mapping = {
                'readOnly': 'read_only',
                'type': 'type',
                'format': 'format',
                'description': 'description',
                'default': 'default',
                'minimum': 'minimum',
                'maximum': 'maximum',
                'enum': 'enum',
                '$ref': '$ref',
                'items': 'items',
            }
            for f_key, d_key in list(data_mapping.items()):
                if field_data[d_key]:
                    f[f_key] = field_data[d_key]

            # memorize discovered field
            data['fields'][name] = f
        return data

