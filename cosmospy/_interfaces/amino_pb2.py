# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: amino.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import descriptor_pb2 as google_dot_protobuf_dot_descriptor__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0b\x61mino.proto\x12\x05\x61mino\x1a google/protobuf/descriptor.proto:0\n\x04name\x12\x1f.google.protobuf.MessageOptions\x18\xf1\x8c\xa6\x05 \x01(\t:<\n\x10message_encoding\x12\x1f.google.protobuf.MessageOptions\x18\xf2\x8c\xa6\x05 \x01(\t:2\n\x08\x65ncoding\x12\x1d.google.protobuf.FieldOptions\x18\xf3\x8c\xa6\x05 \x01(\t:4\n\nfield_name\x12\x1d.google.protobuf.FieldOptions\x18\xf4\x8c\xa6\x05 \x01(\t:8\n\x0e\x64ont_omitempty\x12\x1d.google.protobuf.FieldOptions\x18\xf5\x8c\xa6\x05 \x01(\x08\x42-Z+github.com/cosmos/cosmos-sdk/types/tx/aminob\x06proto3')


NAME_FIELD_NUMBER = 11110001
name = DESCRIPTOR.extensions_by_name['name']
MESSAGE_ENCODING_FIELD_NUMBER = 11110002
message_encoding = DESCRIPTOR.extensions_by_name['message_encoding']
ENCODING_FIELD_NUMBER = 11110003
encoding = DESCRIPTOR.extensions_by_name['encoding']
FIELD_NAME_FIELD_NUMBER = 11110004
field_name = DESCRIPTOR.extensions_by_name['field_name']
DONT_OMITEMPTY_FIELD_NUMBER = 11110005
dont_omitempty = DESCRIPTOR.extensions_by_name['dont_omitempty']

if _descriptor._USE_C_DESCRIPTORS == False:
  google_dot_protobuf_dot_descriptor__pb2.MessageOptions.RegisterExtension(name)
  google_dot_protobuf_dot_descriptor__pb2.MessageOptions.RegisterExtension(message_encoding)
  google_dot_protobuf_dot_descriptor__pb2.FieldOptions.RegisterExtension(encoding)
  google_dot_protobuf_dot_descriptor__pb2.FieldOptions.RegisterExtension(field_name)
  google_dot_protobuf_dot_descriptor__pb2.FieldOptions.RegisterExtension(dont_omitempty)

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z+github.com/cosmos/cosmos-sdk/types/tx/amino'
# @@protoc_insertion_point(module_scope)