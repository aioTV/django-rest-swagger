# -*- coding: utf-8 -*-
from collections import OrderedDict

import rest_framework
import inspect

from django.utils import six
from rest_framework.compat import apply_markdown
from .constants import INTROSPECTOR_PRIMITIVES
import collections


def get_serializer_name(serializer, write=False):
        prefix = "Write" if write else ""
        if serializer is None:
            return None
        if rest_framework.VERSION >= '3.0.0':
            from rest_framework.serializers import ListSerializer
            assert serializer != ListSerializer, "uh oh, what now?"
            if isinstance(serializer, ListSerializer):
                serializer = serializer.child

        if hasattr(serializer, 'Meta') and hasattr(serializer.Meta, 'swagger_name') and serializer.Meta.swagger_name:
            return prefix + serializer.Meta.swagger_name

        if not inspect.isclass(serializer):
            serializer = serializer.__class__

        if serializer.__name__.endswith("Serializer"):
            return prefix + serializer.__name__[:-len("Serializer")]

        return prefix + serializer.__name__


def get_view_description(view_cls, html=False, docstring=None):
    if docstring is not None:
        view_cls = type(
            view_cls.__name__ + '_fake',
            (view_cls,),
            {'__doc__': docstring})
    return rest_framework.settings.api_settings \
        .VIEW_DESCRIPTION_FUNCTION(view_cls, html)


def get_default_value(field):
    default_value = getattr(field, 'default', None)
    if rest_framework.VERSION >= '3.0.0':
        from rest_framework.fields import empty
        if default_value == empty:
            default_value = None
    if isinstance(default_value, collections.Callable):
        default_value = default_value()
    return default_value


def do_markdown(docstring):
    # Markdown is optional
    if apply_markdown:
        return apply_markdown(docstring)
    else:
        return docstring.replace("\n\n", "<br/>")


def multi_getattr(obj, attr, default=None):
    """
    Get a named attribute from an object; multi_getattr(x, 'a.b.c.d') is
    equivalent to x.a.b.c.d. When a default argument is given, it is
    returned when any attribute in the chain doesn't exist; without
    it, an exception is raised when a missing attribute is encountered.

    """
    attributes = attr.split(".")
    for i in attributes:
        try:
            obj = getattr(obj, i)
        except AttributeError:
            if default:
                return default
            else:
                raise
    return obj


def get_normalized_data_format(data_type, data_format):
    """
    If data_format is provided, it will be used unless invalidated for some reason. Swagger 2.0
    allows any string as a format. If no data_format is provided, a default may be returned.
    Returns None if no format should be set.
    """
    if data_type == 'array':
        return None
    if not data_format:
        return next(iter(INTROSPECTOR_PRIMITIVES.get(data_type, [])), None)
    if data_format == data_type:
        return None
    return data_format


def normalize_data_format(data_type, data_format, obj):
    """
    sets 'type' and 'format' on obj
    """
    data_format = get_normalized_data_format(data_type, data_format)

    obj['type'] = data_type
    if data_format is None and 'format' in obj:
        del obj['format']
    elif data_format is not None:
        obj['format'] = data_format


def tag_from_prefix(url_path):
    leading_segment = url_path.strip("/").split('/')[0]
    if leading_segment:
        return [leading_segment]
    return []


def template_dict(root, find, replace):
    if hasattr(root, 'items'):
        return OrderedDict([
            replace if (k, v) == find else (k, template_dict(v, find, replace))
            for k, v in list(root.items())
        ])
    if isinstance(root, list):
        return [template_dict(v, find, replace) for v in root]
    return root


def find_refs(root):
    refs = set()
    if hasattr(root, 'items'):
        for key, value in list(root.items()):
            if key == '$ref' and value.startswith("#/definitions/"):
                refs.add(value[len("#/definitions/"):])
            else:
                refs.update(find_refs(value))
    elif hasattr(root, '__iter__') and not isinstance(root, six.string_types):
        for value in root:
            refs.update(find_refs(value))
    return refs


def find_used_refs(roots, definitions):
    used_definitions = set(roots)
    for root in roots:
        extra_roots = find_refs(definitions[root]) - used_definitions
        used_definitions.update(find_used_refs(extra_roots, definitions))
    return used_definitions


def get_child(parent_serializer):
    """
    Extract the child serializer from a parent serializer (e.g. ListSerializer).
    """
    # DRF handled this differently in older versions, so try both ways
    meta = getattr(parent_serializer, 'Meta', None)
    meta_child = getattr(meta, 'child', None)
    serializer_child = getattr(parent_serializer, 'child', None)
    return meta_child or serializer_child
