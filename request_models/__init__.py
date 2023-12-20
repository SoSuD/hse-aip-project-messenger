import string

from marshmallow import Schema, fields, validate, ValidationError


class CustomSchema(Schema):
    def handle_error(self, exception: ValidationError, data, **kwargs):
        raise ValidationError({'succeeded': False, 'errors': {k: v for k, v in exception.messages.items()}})


class UserCredentials(CustomSchema):
    username = fields.String(required=True, validate=[
        validate.Length(min=5),
        validate.ContainsOnly(string.ascii_letters + string.digits)
    ])
    password = fields.String(required=True, validate=validate.Length(6, 32))
    system_id = fields.String(required=True)
    application_id = fields.UUID(required=True)


class DHKeyRequest(CustomSchema):
    algo = fields.String(required=True)
    value = fields.String(required=True)


class SessionKeyRequest(CustomSchema):
    algo = fields.String(required=True)
    value = fields.String(required=True)
    iv = fields.String(required=True)


class MessageRequest(CustomSchema):
    content = fields.String(required=True)


class SortRequest(CustomSchema):
    items = fields.Integer(validate=validate.Range(min=0), load_default=50)
    page = fields.Integer(validate=validate.Range(min=0), load_default=0)
    order = fields.String(validate=lambda order: order in ('desc', 'asc'), load_default='desc')
