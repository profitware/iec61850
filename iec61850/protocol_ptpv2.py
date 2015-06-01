#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Sergey Sobko'
__email__ = 'S.Sobko@profitware.ru'
__copyright__ = 'Copyright 2015, The Profitware Group'

from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether


class PTPv2(Packet):
    """PTPv2 Protocol."""

    # FIXME: Implement fields.

    name = 'PTPv2'


bind_layers(Ether, PTPv2, type=0x88f7)
