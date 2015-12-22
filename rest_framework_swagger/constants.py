# -*- coding: utf-8 -*-

INTROSPECTOR_ENUMS = [
    'choice',
    'multiple choice',
]

INTROSPECTOR_PRIMITIVES = {
    'integer': ['int32', 'int64'],
    'number': ['float', 'double'],
    'string': ['string', 'byte', 'date', 'date-time', 'password'],
    'boolean': ['boolean'],
}

DEFAULT_PAGE_DEFINITION = {
    "type": "object",
    "properties": {
        "count": {
            "type": "integer",
            "format": "int64",
        },
        "next": {
            "type": "string"
        },
        "previous": {
            "type": "string"
        },
        "results": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/*"
            }
        }
    }
}