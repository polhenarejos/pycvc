# -*- coding: utf-8 -*-
"""
/*
 * This file is part of the pyCVC distribution (https://github.com/polhenarejos/pycvc).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
"""

from cvc.utils import to_bytes

class ASN1:
    DER = 1

    _TAG_OID = 0x6
    _TAG_CONTEXT = 0x80

    def __init__(self):
        self._buffer = b''
        self._context_counter = 0

    def calculate_len(size):
        if (size <= 0x7f):
            return bytearray([size])
        b = to_bytes(size)
        return bytearray([0x80+len(b)]) + b

    def make_tag(tag, b):
        return to_bytes(tag) + ASN1.calculate_len(len(b)) + bytearray(b)

    def make_context(tag, n):
        return ASN1.make_tag(tag, to_bytes(n))

    def make_oid(oid):
        return ASN1.make_tag(ASN1._TAG_OID, oid)

    def _append_buffer(self, b):
        self._buffer = self._buffer + b

    def add_tag(self, tag, b):
        self._append_buffer(ASN1.make_tag(tag, b))
        return self

    def add_context(self, b):
        self._context_counter = self._context_counter + 1
        if (b != None):
            return self.add_tag(ASN1._TAG_CONTEXT + self._context_counter, b)
        return self

    def add_oid(self, b):
        return self.add_tag(ASN1._TAG_OID, b)

    def add_object(self, tag, oid, ctxs):
        ta = ASN1().add_oid(oid)
        for c in ctxs:
            ta.add_context(c)
        self.add_tag(tag, ta.encode())
        return self

    def encode(self, encoding_type = DER):
        return self._buffer

    def decode(self, data, encoding_type = DER):
        self._buffer = bytearray(data)
        return self

    def all(self):
        p = 0
        while p < len(self._buffer):
            tag = self._buffer[p]
            p += 1
            if ((tag & 0x1f) == 0x1f):
                tag = (tag << 8) | self._buffer[p]
                p += 1
            if ((self._buffer[p] & 0x80) == 0x80):
                n = self._buffer[p] & 0x7f
                p += 1
                l = 0
                for i in range(n):
                    l = l | (self._buffer[p+i] << 8*(n-i-1))
                p += n
            else:
                l = self._buffer[p]
                p += 1
            d = self._buffer[p:p+l]
            p += l
            yield (tag, d)

    def find(self, tag, pos=0):
        pos_counter = 0
        for t, d in self.all():
            if (tag == t):
                if (pos_counter == pos):
                    self._buffer = d
                    self._current_tag = tag
                    return self
                pos_counter += 1
        return None

    def data(self, return_tag=False):
        if (return_tag is True):
            return ASN1.make_tag(self._current_tag, self._buffer)
        return self._buffer

    def oid(self):
        return self.find(0x6).data()
