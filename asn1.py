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

from utils import to_bytes

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
        return to_bytes(tag) + ASN1.calculate_len(len(b)) + b
    
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
        return self.add_tag(ASN1._TAG_CONTEXT + self._context_counter, b)
    
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
        