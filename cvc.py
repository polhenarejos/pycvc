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

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
import datetime
from utils import to_bytes, bcd, get_hash_padding
from ec_curves import ec_domain
from asn1 import ASN1

class CVC:
    __data = None
    def __init__(self):
        self.__a = ASN1()
        
    def decode(self, data):
        self.__data = data
        self.__a = ASN1().decode(self.__data)
        return self
        
    def body(self, pubkey = None, scheme = None, car = None, chr = None, role = None, valid = None, since = None, extensions = None):
        if (self.__data != None):
            return self.cert().find(0x7f4e)
        self.__a = ASN1().add_tag(0x7f4e, self.cpi().car(car).pubkey(pubkey, scheme, car == chr).chr(chr).role(role).valid(valid, since).encode())
        return self
    
    def car(self, car = None):
        if (self.__data != None):
            return self.body().find(0x42).data()
        self.__a = self.__a.add_tag(0x42, car)
        return self
    
    def outer_car(self):
        return self.req().find(0x42).data()
    
    def chr(self, chr = None):
        if (self.__data != None):
            return self.body().find(0x5f20).data()
        self.__a = self.__a.add_tag(0x5f20, chr)
        return self
    
    def cpi(self, val = 0):
        if (self.__data != None):
            return self.body().find(0x5f29).data()
        self.__a = self.__a.add_tag(0x5f29, to_bytes(val))
        return self
        
    def pubkey(self, pubkey = None, scheme = None, full = None):
        if (self.__data != None):
            return self.body().find(0x7f49)
        if (isinstance(pubkey, rsa.RSAPublicKey)):
            pubctx = [pubkey.public_numbers().n, pubkey.public_numbers().e]
        elif (isinstance(pubkey, ec.EllipticCurvePublicKey)):
            dom = ec_domain(pubkey.public_numbers().curve)
            Y = pubkey.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            if (full):
                pubctx = [dom.P, dom.A, dom.B, dom.G, dom.O, Y, dom.F]
            else:
                pubctx = [None, None, None, None, None, Y, None]
        self.__a = self.__a.add_object(0x7f49, scheme, pubctx)
        return self
    
    def role(self, role = None):
        if (self.__data != None):
            return self.body().find(0x7f4c)
        if (role != None):
            self.__a = self.__a.add_tag(0x7f4c, ASN1().add_oid(role.OID).add_tag(0x53, role.to_bytes()).encode())
        return self
    
    def valid(self, valid = None, since = None):
        if (self.__data != None):
            return self.body().find(0x5f25).data()
        if (valid != None):
            if (since == None):
                since = datetime.datetime.now().strftime("%y%m%d")
            until = (datetime.datetime.strptime(since, "%y%m%d") + datetime.timedelta(days = valid)).strftime("%y%m%d")
            self.__a = self.__a.add_tag(0x5f25, bcd(since)).add_tag(0x5f24, bcd(until))
        return self
    
    def expires(self):
        return self.body().find(0x5f24).data()
        
    def signature(self):
        if (self.__data != None):
            return self.cert().find(0x5f37).data()
        
    def outer_signature(self):
        if (self.__data != None):
            return self.req().find(0x5f37).data()
        
    def sign(self, key, scheme):
        h,p = get_hash_padding(scheme)
        if (isinstance(key, ec.EllipticCurvePrivateKey)):
            signature = key.sign(self.__a.encode(), ec.ECDSA(h))
            r,s = utils.decode_dss_signature(signature)
            signature = to_bytes(r) + to_bytes(s)
        elif (isinstance(key, rsa.RSAPrivateKey)):
            signature = key.sign(self.__a.encode(), p, h)
        self.__a = self.__a.add_tag(0x5f37, bytearray(signature))
        return self

    def cert(self, pubkey = None, scheme = None, signkey = None, signscheme = None, car = None, chr = None, role = None, valid = None, since = None, extensions = None):
        if (self.__data != None):
            return self.req().find(0x7f21)
        self.__a = ASN1().add_tag(0x7f21, self.body(pubkey, scheme, car, chr, role, valid, since, extensions).sign(signkey, signscheme).encode())
        return self
    
    def req(self, pubkey = None, scheme = None, signkey = None, signscheme = None, car = None, chr = None, outercar = None, outerkey = None, outerscheme = None, extensions = None):
        if (self.__data != None):
            aut = self.__a.find(0x67)
            if (aut):
                return aut
            return self.__a
        cert = self.cert(pubkey, scheme, signkey, signscheme, car, chr, role=None, valid=None, since=None, extensions=extensions)
        if (outercar != None and outerkey != None and outerscheme != None):
            self.__a = ASN1().add_tag(0x67, cert.car(outercar).sign(outerkey, outerscheme).encode())
        return self
    
    def encode(self):
        return self.__a.encode()
