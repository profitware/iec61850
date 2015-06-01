#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Sergey Sobko'
__email__ = 'S.Sobko@profitware.ru'
__copyright__ = 'Copyright 2015, The Profitware Group'

from scapy.all import sniff
from scapy.utils import rdpcap


def use_pcap(prn=None, lfilter=None, filename=None):
    pcp = rdpcap(filename=filename)

    if prn is None:
        prn = lambda pkt: pkt

    if lfilter is None:
        lfilter = lambda pkt: True

    for packet in pcp:
        if lfilter(packet):
            out_line = prn(packet)

            if out_line:
                print out_line


def use_sniff(prn=None, lfilter=None, filename=None):
    sniff(prn=prn, lfilter=lfilter)
