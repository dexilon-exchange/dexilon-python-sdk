# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: authz.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import cosmospy._interfaces.amino_pb2 as amino__pb2
import cosmospy._interfaces.cosmos_pb2 as cosmos__pb2
from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2
import cosmospy._interfaces.gogo_pb2 as gogo__pb2
import cosmospy._interfaces.any_pb2 as any__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='authz.proto',
  package='cosmos.authz.v1beta1',
  syntax='proto3',
  serialized_options=b'Z$github.com/cosmos/cosmos-sdk/x/authz\310\341\036\000',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0b\x61uthz.proto\x12\x14\x63osmos.authz.v1beta1\x1a\x0b\x61mino.proto\x1a\x0c\x63osmos.proto\x1a\x1fgoogle/protobuf/timestamp.proto\x1a\ngogo.proto\x1a\tany.proto\"Z\n\x14GenericAuthorization\x12\x0b\n\x03msg\x18\x01 \x01(\t:5\x8a\xe7\xb0*\x1f\x63osmos-sdk/GenericAuthorization\xca\xb4-\rAuthorization\"\x81\x01\n\x05Grant\x12>\n\rauthorization\x18\x01 \x01(\x0b\x32\x14.google.protobuf.AnyB\x11\xca\xb4-\rAuthorization\x12\x38\n\nexpiration\x18\x02 \x01(\x0b\x32\x1a.google.protobuf.TimestampB\x08\x90\xdf\x1f\x01\xc8\xde\x1f\x01\"\xe0\x01\n\x12GrantAuthorization\x12)\n\x07granter\x18\x01 \x01(\tB\x18\xd2\xb4-\x14\x63osmos.AddressString\x12)\n\x07grantee\x18\x02 \x01(\tB\x18\xd2\xb4-\x14\x63osmos.AddressString\x12>\n\rauthorization\x18\x03 \x01(\x0b\x32\x14.google.protobuf.AnyB\x11\xca\xb4-\rAuthorization\x12\x34\n\nexpiration\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.TimestampB\x04\x90\xdf\x1f\x01\"\'\n\x0eGrantQueueItem\x12\x15\n\rmsg_type_urls\x18\x01 \x03(\tB*Z$github.com/cosmos/cosmos-sdk/x/authz\xc8\xe1\x1e\x00\x62\x06proto3'
  ,
  dependencies=[amino__pb2.DESCRIPTOR,cosmos__pb2.DESCRIPTOR,google_dot_protobuf_dot_timestamp__pb2.DESCRIPTOR,gogo__pb2.DESCRIPTOR,any__pb2.DESCRIPTOR,])




_GENERICAUTHORIZATION = _descriptor.Descriptor(
  name='GenericAuthorization',
  full_name='cosmos.authz.v1beta1.GenericAuthorization',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='msg', full_name='cosmos.authz.v1beta1.GenericAuthorization.msg', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=b'\212\347\260*\037cosmos-sdk/GenericAuthorization\312\264-\rAuthorization',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=120,
  serialized_end=210,
)


_GRANT = _descriptor.Descriptor(
  name='Grant',
  full_name='cosmos.authz.v1beta1.Grant',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='authorization', full_name='cosmos.authz.v1beta1.Grant.authorization', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\312\264-\rAuthorization', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='expiration', full_name='cosmos.authz.v1beta1.Grant.expiration', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\220\337\037\001\310\336\037\001', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=213,
  serialized_end=342,
)


_GRANTAUTHORIZATION = _descriptor.Descriptor(
  name='GrantAuthorization',
  full_name='cosmos.authz.v1beta1.GrantAuthorization',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='granter', full_name='cosmos.authz.v1beta1.GrantAuthorization.granter', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\322\264-\024cosmos.AddressString', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='grantee', full_name='cosmos.authz.v1beta1.GrantAuthorization.grantee', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\322\264-\024cosmos.AddressString', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='authorization', full_name='cosmos.authz.v1beta1.GrantAuthorization.authorization', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\312\264-\rAuthorization', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='expiration', full_name='cosmos.authz.v1beta1.GrantAuthorization.expiration', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=b'\220\337\037\001', file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=345,
  serialized_end=569,
)


_GRANTQUEUEITEM = _descriptor.Descriptor(
  name='GrantQueueItem',
  full_name='cosmos.authz.v1beta1.GrantQueueItem',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='msg_type_urls', full_name='cosmos.authz.v1beta1.GrantQueueItem.msg_type_urls', index=0,
      number=1, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=571,
  serialized_end=610,
)

_GRANT.fields_by_name['authorization'].message_type = any__pb2._ANY
_GRANT.fields_by_name['expiration'].message_type = google_dot_protobuf_dot_timestamp__pb2._TIMESTAMP
_GRANTAUTHORIZATION.fields_by_name['authorization'].message_type = any__pb2._ANY
_GRANTAUTHORIZATION.fields_by_name['expiration'].message_type = google_dot_protobuf_dot_timestamp__pb2._TIMESTAMP
DESCRIPTOR.message_types_by_name['GenericAuthorization'] = _GENERICAUTHORIZATION
DESCRIPTOR.message_types_by_name['Grant'] = _GRANT
DESCRIPTOR.message_types_by_name['GrantAuthorization'] = _GRANTAUTHORIZATION
DESCRIPTOR.message_types_by_name['GrantQueueItem'] = _GRANTQUEUEITEM
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

GenericAuthorization = _reflection.GeneratedProtocolMessageType('GenericAuthorization', (_message.Message,), {
  'DESCRIPTOR' : _GENERICAUTHORIZATION,
  '__module__' : 'authz_pb2'
  # @@protoc_insertion_point(class_scope:cosmos.authz.v1beta1.GenericAuthorization)
  })
_sym_db.RegisterMessage(GenericAuthorization)

Grant = _reflection.GeneratedProtocolMessageType('Grant', (_message.Message,), {
  'DESCRIPTOR' : _GRANT,
  '__module__' : 'authz_pb2'
  # @@protoc_insertion_point(class_scope:cosmos.authz.v1beta1.Grant)
  })
_sym_db.RegisterMessage(Grant)

GrantAuthorization = _reflection.GeneratedProtocolMessageType('GrantAuthorization', (_message.Message,), {
  'DESCRIPTOR' : _GRANTAUTHORIZATION,
  '__module__' : 'authz_pb2'
  # @@protoc_insertion_point(class_scope:cosmos.authz.v1beta1.GrantAuthorization)
  })
_sym_db.RegisterMessage(GrantAuthorization)

GrantQueueItem = _reflection.GeneratedProtocolMessageType('GrantQueueItem', (_message.Message,), {
  'DESCRIPTOR' : _GRANTQUEUEITEM,
  '__module__' : 'authz_pb2'
  # @@protoc_insertion_point(class_scope:cosmos.authz.v1beta1.GrantQueueItem)
  })
_sym_db.RegisterMessage(GrantQueueItem)


DESCRIPTOR._options = None
_GENERICAUTHORIZATION._options = None
_GRANT.fields_by_name['authorization']._options = None
_GRANT.fields_by_name['expiration']._options = None
_GRANTAUTHORIZATION.fields_by_name['granter']._options = None
_GRANTAUTHORIZATION.fields_by_name['grantee']._options = None
_GRANTAUTHORIZATION.fields_by_name['authorization']._options = None
_GRANTAUTHORIZATION.fields_by_name['expiration']._options = None
# @@protoc_insertion_point(module_scope)
