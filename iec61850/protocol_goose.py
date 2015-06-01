#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Sergey Sobko'
__email__ = 'S.Sobko@profitware.ru'
__copyright__ = 'Copyright 2015, The Profitware Group'

from struct import pack, unpack

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ShortField, StrLenField, FieldLenField, StrField
from scapy.layers.l2 import Ether


class TimestampField(StrLenField):
    """2 dwords for timestamp."""

    # FIXME: How to combine first and second word to get standard datetime?

    def m2i(self, pkt, x):
        if len(x) == 8:
            return unpack('>LL', x)

        if len(x) == 4:
            return unpack('>L', x)[0], None

        return None, None

    def i2m(self, pkt, x):
        if isinstance(x, int):
            int_part, float_part = x, None
        else:
            int_part, float_part = x

        if int_part:
            if float_part:
                return pack('>LL', (int_part, float_part))
            return pack('>L', int_part)

        return None


class GoosePDUAdditional(StrField):
    """One or two bytes before goosePdu."""

    # FIXME: Investigate the meaning of this field.

    def getfield(self, pkt, s):
        if s[0] == '\x60':
            l = 1
        else:
            l = 2
        return s[l:], self.m2i(pkt, s[:l])


class GOOSE(Packet):
    """Generic Object Oriented Secure Event protocol."""

    name = 'GOOSE'
    fields_desc = [
        ShortField('APPID', 0),
        ShortField('Length', 0),
        ShortField('Reserved 1', 0),
        ShortField('Reserved 2', 0),

        # FIXME: Maybe extract goosePDU into its own class?

        ByteField('GoosePDU 0x61', 0x61),

        GoosePDUAdditional('GoosePDU Additional', None),

        ByteField('gocbRefField', 0x80),
        FieldLenField('gocbRefLength', None, 'gocbRef', fmt='B'),
        StrLenField('gocbRef', '', length_from=lambda pkt: pkt.gocbRefLength),

        ByteField('timeAllowedToLiveField', 0x81),
        FieldLenField('timeAllowedToLiveLength', None, 'timeAllowedToLive', fmt='B'),
        ShortField('timeAllowedToLive', 0),

        ByteField('datSetField', 0x82),
        FieldLenField('datSetLength', None, 'datSet', fmt='B'),
        StrLenField('datSet', '', length_from=lambda pkt: pkt.datSetLength),

        ByteField('goIdField', 0x83),
        FieldLenField('goIdLength', None, 'goId', fmt='B'),
        StrLenField('goId', '', length_from=lambda pkt: pkt.goIdLength),

        ByteField('tField', 0x84),
        FieldLenField('tLength', None, 't', fmt='B'),
        TimestampField('t', '', length_from=lambda pkt: pkt.tLength),

        ByteField('stNumField', 0x85),
        FieldLenField('stNumLength', None, 'stNum', fmt='B'),
        ByteField('stNum', ''),

        ByteField('sqNumField', 0x86),
        FieldLenField('sqNumLength', None, 'sqNum', fmt='B'),
        ShortField('sqNum', ''),

        ByteField('testField', 0x87),
        FieldLenField('testLength', None, 'testNum', fmt='B'),
        ByteField('testNum', ''),

        ByteField('confRevField', 0x88),
        FieldLenField('confRevLength', None, 'confRevNum', fmt='B'),
        ByteField('confRevNum', ''),

        ByteField('ndsComField', 0x89),
        FieldLenField('ndsComLength', None, 'ndsCom', fmt='B'),
        ByteField('ndsCom', ''),

        ByteField('numDataSetEntriesField', 0x8a),
        FieldLenField('numDataSetEntriesLength', None, 'numDataSetEntries', fmt='B'),
        ByteField('numDataSetEntries', ''),

        # FIXME: Decode payload.

        StrField('goosePayload', '')

    ]


bind_layers(Ether, GOOSE, type=0x88b8)
