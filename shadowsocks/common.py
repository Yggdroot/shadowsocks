#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket
import struct
import logging


ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3


def pack_addr(address):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            r = socket.inet_pton(family, address)
            if family == socket.AF_INET6:
                return b'\x04' + r
            else:
                return b'\x01' + r
        except (TypeError, ValueError, OSError, IOError):
            pass
    if len(address) > 255:
        address = address[:255]  # TODO
    return ('\x03' + chr(len(address)) + address).encode('ascii')


def parse_header(data):
    addrtype = ord(data[0:1])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype == ADDRTYPE_IPV4:
        if len(data) >= 7:
            dest_addr = socket.inet_ntoa(data[1:5])
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1:2])
            if len(data) >= 2 + addrlen:
                dest_addr = data[2:2 + addrlen].decode('ascii')
                dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                          addrlen])[0]
                header_length = 4 + addrlen
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_IPV6:
        if len(data) >= 19:
            dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            dest_port = struct.unpack('>H', data[17:19])[0]
            header_length = 19
        else:
            logging.warn('header is too short')
    else:
        logging.warn('unsupported addrtype %d, maybe wrong password',
                     addrtype)
    if dest_addr is None:
        return None
    return addrtype, dest_addr, dest_port, header_length


def test_inet_conv():
    ipv4 = '8.8.4.4'
    b = socket.inet_pton(socket.AF_INET, ipv4)
    assert socket.inet_ntop(socket.AF_INET, b) == ipv4
    ipv6 = '2404:6800:4005:805::1011'
    b = socket.inet_pton(socket.AF_INET6, ipv6)
    assert socket.inet_ntop(socket.AF_INET6, b) == ipv6


def test_parse_header():
    assert parse_header(b'\x03\x0ewww.google.com\x00\x50') == \
        (3, 'www.google.com', 80, 18)
    assert parse_header(b'\x01\x08\x08\x08\x08\x00\x35') == \
        (1, '8.8.8.8', 53, 7)
    assert parse_header((b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00'
                         b'\x00\x10\x11\x00\x50')) == \
        (4, '2404:6800:4005:805::1011', 80, 19)


def test_pack_header():
    assert pack_addr('8.8.8.8') == b'\x01\x08\x08\x08\x08'
    assert pack_addr('2404:6800:4005:805::1011') == \
        b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00\x00\x10\x11'
    assert pack_addr('www.google.com') == b'\x03\x0ewww.google.com'


if __name__ == '__main__':
    test_inet_conv()
    test_parse_header()
    test_pack_header()
