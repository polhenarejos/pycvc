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
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils
from cryptography.hazmat.primitives import hashes
import datetime
import oid
from utils import to_bytes, bcd
from ec_curves import ec_domain
from asn1 import ASN1

class CVC:
    def __init__(self):
        self.__a = ASN1()
        
    def body(self, pubkey, scheme, car, chr, role = None, valid = None, since = None, extensions = None):
        self.__a = ASN1().add_tag(0x7f4e, self.cpi().car(car).pubkey(pubkey, scheme, car == chr).chr(chr).role(role).valid(valid, since).encode())
        return self
    
    def car(self, car):
        self.__a = self.__a.add_tag(0x42, car)
        return self
    
    def chr(self, chr):
        self.__a = self.__a.add_tag(0x5f20, chr)
        return self
    
    def cpi(self, val = 0):
        self.__a = self.__a.add_tag(0x5f29, to_bytes(val))
        return self
        
    def pubkey(self, pubkey, scheme, full):
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
    
    def role(self, role):
        if (role != None):
            self.__a = self.__a.add_tag(0x7f4c, ASN1().add_oid(role.OID).add_tag(0x53, role.to_bytes()).encode())
        return self
    
    def valid(self, valid, since = None):
        if (valid != None):
            if (since == None):
                since = datetime.datetime.now().strftime("%y%m%d")
            until = (datetime.datetime.strptime(since, "%y%m%d") + datetime.timedelta(days = valid)).strftime("%y%m%d")
            self.__a = self.__a.add_tag(0x5f25, bcd(since)).add_tag(0x5f24, bcd(until))
        return self
    
    def sign(self, key, scheme):
        if (scheme == oid.ID_TA_ECDSA_SHA_1 or scheme == oid.ID_TA_RSA_PSS_SHA_1 or scheme == oid.ID_TA_RSA_V1_5_SHA_1):
            h = hashes.SHA1()
        elif (scheme == oid.ID_TA_ECDSA_SHA_224):
            h = hashes.SHA224()
        elif (scheme == oid.ID_TA_ECDSA_SHA_256 or scheme == oid.ID_TA_RSA_PSS_SHA_256 or scheme == oid.ID_TA_RSA_V1_5_SHA_256):
            h = hashes.SHA256()
        elif (scheme == oid.ID_TA_ECDSA_SHA_384):
            h = hashes.SHA384()
        elif (scheme == oid.ID_TA_ECDSA_SHA_512 or scheme == oid.ID_TA_RSA_PSS_SHA_512 or scheme == oid.ID_TA_RSA_V1_5_SHA_512):
            h = hashes.SHA512()
        if (isinstance(key, ec.EllipticCurvePrivateKey)):
            signature = key.sign(self.__a.encode(), ec.ECDSA(h))
            r,s = utils.decode_dss_signature(signature)
            signature = to_bytes(r) + to_bytes(s)
        elif (isinstance(key, rsa.RSAPrivateKey)):
            if (scheme == oid.ID_TA_RSA_V1_5_SHA_1 or scheme == oid.ID_TA_RSA_V1_5_SHA_256 or scheme == oid.ID_TA_RSA_V1_5_SHA_512):
                p = padding.PKCS1v15()
            elif (scheme == oid.ID_TA_RSA_PSS_SHA_1 or scheme == oid.ID_TA_RSA_PSS_SHA_256 or scheme == oid.ID_TA_RSA_PSS_SHA_512):
                p = padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.MAX_LENGTH)
            signature = key.sign(self.__a.buffer(), p, h)
        self.__a = self.__a.add_tag(0x5f37, bytearray(signature))
        return self

    def cert(self, pubkey, scheme, signkey, signscheme, car, chr, role, valid, since = None, extensions = None):
        self.__a = ASN1().add_tag(0x7f21, self.body(pubkey, scheme, car, chr, role, valid, since, extensions).sign(signkey, signscheme).encode())
        return self
    
    def req(self, pubkey, scheme, signkey, signscheme, car, chr, outercar = None, outerkey = None, outerscheme = None, extensions = None):
        cert = self.cert(pubkey, scheme, signkey, signscheme, car, chr, role=None, valid=None, since=None, extensions=extensions)
        if (outercar != None and outerkey != None and outerscheme != None):
            self.__a = ASN1().add_tag(0x67, cert.car(outercar).sign(outerkey, outerscheme).encode())
        return self
    
    def encode(self):
        return self.__a.encode()
