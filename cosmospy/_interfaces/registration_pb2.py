# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: registration.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x12registration.proto\x12\'dexilon_exchange.dexilonL2.registration\"v\n\x17MsgCreateAddressMapping\x12\x0f\n\x07\x63reator\x18\x01 \x01(\t\x12\x0f\n\x07\x63hainId\x18\x02 \x01(\x05\x12\x0f\n\x07\x61\x64\x64ress\x18\x03 \x01(\t\x12\x11\n\tsignature\x18\x04 \x01(\t\x12\x15\n\rsignedMessage\x18\x05 \x01(\t\"\x89\x01\n\x19MsgGrantPermissionRequest\x12\x0f\n\x07\x63reator\x18\x01 \x01(\t\x12\x19\n\x11granterEthAddress\x18\x02 \x01(\t\x12\x11\n\tsignature\x18\x03 \x01(\t\x12\x15\n\rsignedMessage\x18\x04 \x01(\t\x12\x16\n\x0e\x65xpirationTime\x18\x05 \x01(\x04\"r\n\x1aMsgRevokePermissionRequest\x12\x0f\n\x07\x63reator\x18\x01 \x01(\t\x12\x19\n\x11granterEthAddress\x18\x02 \x01(\t\x12\x11\n\tsignature\x18\x03 \x01(\t\x12\x15\n\rsignedMessage\x18\x04 \x01(\t\"\x12\n\x10MsgEmptyResponse2\xc3\x03\n\x03Msg\x12\x93\x01\n\x14\x43reateAddressMapping\x12@.dexilon_exchange.dexilonL2.registration.MsgCreateAddressMapping\x1a\x39.dexilon_exchange.dexilonL2.registration.MsgEmptyResponse\x12\x90\x01\n\x0fGrantPermission\x12\x42.dexilon_exchange.dexilonL2.registration.MsgGrantPermissionRequest\x1a\x39.dexilon_exchange.dexilonL2.registration.MsgEmptyResponse\x12\x92\x01\n\x10RevokePermission\x12\x43.dexilon_exchange.dexilonL2.registration.MsgRevokePermissionRequest\x1a\x39.dexilon_exchange.dexilonL2.registration.MsgEmptyResponseB<Z:github.com/dexilon-exchange/dexilonL2/x/registration/typesb\x06proto3')



_MSGCREATEADDRESSMAPPING = DESCRIPTOR.message_types_by_name['MsgCreateAddressMapping']
_MSGGRANTPERMISSIONREQUEST = DESCRIPTOR.message_types_by_name['MsgGrantPermissionRequest']
_MSGREVOKEPERMISSIONREQUEST = DESCRIPTOR.message_types_by_name['MsgRevokePermissionRequest']
_MSGEMPTYRESPONSE = DESCRIPTOR.message_types_by_name['MsgEmptyResponse']
MsgCreateAddressMapping = _reflection.GeneratedProtocolMessageType('MsgCreateAddressMapping', (_message.Message,), {
  'DESCRIPTOR' : _MSGCREATEADDRESSMAPPING,
  '__module__' : 'registration_pb2'
  # @@protoc_insertion_point(class_scope:dexilon_exchange.dexilonL2.registration.MsgCreateAddressMapping)
  })
_sym_db.RegisterMessage(MsgCreateAddressMapping)

MsgGrantPermissionRequest = _reflection.GeneratedProtocolMessageType('MsgGrantPermissionRequest', (_message.Message,), {
  'DESCRIPTOR' : _MSGGRANTPERMISSIONREQUEST,
  '__module__' : 'registration_pb2'
  # @@protoc_insertion_point(class_scope:dexilon_exchange.dexilonL2.registration.MsgGrantPermissionRequest)
  })
_sym_db.RegisterMessage(MsgGrantPermissionRequest)

MsgRevokePermissionRequest = _reflection.GeneratedProtocolMessageType('MsgRevokePermissionRequest', (_message.Message,), {
  'DESCRIPTOR' : _MSGREVOKEPERMISSIONREQUEST,
  '__module__' : 'registration_pb2'
  # @@protoc_insertion_point(class_scope:dexilon_exchange.dexilonL2.registration.MsgRevokePermissionRequest)
  })
_sym_db.RegisterMessage(MsgRevokePermissionRequest)

MsgEmptyResponse = _reflection.GeneratedProtocolMessageType('MsgEmptyResponse', (_message.Message,), {
  'DESCRIPTOR' : _MSGEMPTYRESPONSE,
  '__module__' : 'registration_pb2'
  # @@protoc_insertion_point(class_scope:dexilon_exchange.dexilonL2.registration.MsgEmptyResponse)
  })
_sym_db.RegisterMessage(MsgEmptyResponse)

_MSG = DESCRIPTOR.services_by_name['Msg']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z:github.com/dexilon-exchange/dexilonL2/x/registration/types'
  _MSGCREATEADDRESSMAPPING._serialized_start=63
  _MSGCREATEADDRESSMAPPING._serialized_end=181
  _MSGGRANTPERMISSIONREQUEST._serialized_start=184
  _MSGGRANTPERMISSIONREQUEST._serialized_end=321
  _MSGREVOKEPERMISSIONREQUEST._serialized_start=323
  _MSGREVOKEPERMISSIONREQUEST._serialized_end=437
  _MSGEMPTYRESPONSE._serialized_start=439
  _MSGEMPTYRESPONSE._serialized_end=457
  _MSG._serialized_start=460
  _MSG._serialized_end=911
# @@protoc_insertion_point(module_scope)
