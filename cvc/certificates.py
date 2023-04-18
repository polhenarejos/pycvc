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

from binascii import hexlify
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.exceptions import InvalidSignature
import datetime
from cvc.utils import to_bytes, bcd, get_hash_padding, scheme_rsa
from cvc.ec_curves import ec_domain, find_curve
from cvc.asn1 import ASN1
import os

class CVC:
    __data=None
    def __init__(self):
        self.__a = ASN1()

    def decode(self, data):
        self.__data = data
        self.__a = ASN1().decode(self.__data)
        return self

    def body(self, pubkey=None, scheme=None, car=None, chr=None, role=None, valid=None, since=None, extensions=None, req=False):
        if (self.__data != None):
            return self.cert().find(0x7f4e)
        self.__a = ASN1().add_tag(0x7f4e, self.cpi().car(car).pubkey(pubkey, scheme, req).chr(chr).role(role).valid(valid, since).extensions(extensions).encode())
        return self

    def extensions(self, extensions=None):
        if (self.__data != None):
            return self.body().find(0x65)
        if (extensions != None):
            data = b''
            for ext in extensions:
                data += ASN1().add_object(tag=ext['tag'], oid=ext['oid'], ctxs=ext['contexts']).encode()
            self.__a = self.__a.add_tag(0x65, data)
        return self

    def car(self, car=None):
        if (self.__data != None):
            return self.body().find(0x42).data()
        self.__a = self.__a.add_tag(0x42, car)
        return self

    def outer_car(self):
        if (self.req().find(0x42)):
            return self.req().find(0x42).data()
        return None

    def chr(self, chr=None):
        if (self.__data != None):
            return self.body().find(0x5f20).data()
        self.__a = self.__a.add_tag(0x5f20, chr)
        return self

    def cpi(self, val = 0):
        if (self.__data != None):
            return self.body().find(0x5f29).data()
        self.__a = self.__a.add_tag(0x5f29, to_bytes(val))
        return self

    def pubkey(self, pubkey=None, scheme=None, full=None):
        if (self.__data != None):
            return self.body().find(0x7f49)
        if (isinstance(pubkey, rsa.RSAPublicKey)):
            pubctx = [to_bytes(pubkey.public_numbers().n), to_bytes(pubkey.public_numbers().e)]
        elif (isinstance(pubkey, ec.EllipticCurvePublicKey)):
            dom = ec_domain(pubkey.public_numbers().curve)
            Y = pubkey.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            if (full):
                pubctx = {1: dom.P, 2: dom.A, 3: dom.B, 4: dom.G, 5: dom.O, 6: Y, 7: dom.F}
            else:
                pubctx = {6: Y}
        self.__a = self.__a.add_object(0x7f49, scheme, pubctx)
        return self

    def role(self, role=None):
        if (self.__data != None):
            return self.body().find(0x7f4c)
        if (role != None):
            self.__a = self.__a.add_tag(0x7f4c, ASN1().add_oid(role.OID).add_tag(0x53, role.to_bytes()).encode())
        return self

    def valid(self, valid=None, since=None):
        if (self.__data != None):
            return self.body().find(0x5f25).data()
        if (valid != None):
            if (since == None):
                since = datetime.datetime.now().strftime("%y%m%d")
            until = (datetime.datetime.strptime(since, "%y%m%d") + datetime.timedelta(days = int(valid))).strftime("%y%m%d")
            self.__a = self.__a.add_tag(0x5f25, bcd(since)).add_tag(0x5f24, bcd(until))
        return self

    def expires(self):
        return self.body().find(0x5f24).data()

    def signature(self):
        if (self.__data != None):
            return self.cert().find(0x5f37).data()

    def outer_signature(self):
        if (self.req().find(0x5f37)):
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

    def cert(self, pubkey=None, scheme=None, signkey=None, signscheme=None, car=None, chr=None, role=None, valid=None, since=None, extensions=None, req=False):
        if (self.__data != None):
            return self.req().find(0x7f21)
        self.__a = ASN1().add_tag(0x7f21, self.body(pubkey, scheme, car, chr, role, valid, since, extensions, req or chr==car).sign(signkey, signscheme).encode())
        return self

    def req(self, pubkey=None, scheme=None, signkey=None, signscheme=None, car=None, chr=None, outercar=None, outerkey=None, outerscheme=None, extensions=None):
        if (self.__data != None):
            aut = ASN1().decode(self.__data).find(0x67)
            if (aut):
                return aut
            return ASN1().decode(self.__data)
        cert = self.cert(pubkey, scheme, signkey, signscheme, car, chr, role=None, valid=None, since=None, extensions=extensions, req=True)
        if (outercar != None and outerkey != None and outerscheme != None):
            self.__a = ASN1().add_tag(0x67, cert.car(outercar).sign(outerkey, outerscheme).encode())
        return self

    def is_req(self):
        if (self.__data != None):
            b = self.__a
            ret = self.__a.find(0x67) != None or self.body().find(0x5f25) == None
            self.__a = b
            return ret
        return False

    def encode(self):
        return self.__a.encode()

    def verify(self, outer=False, cert_dir=None, curve=None, dica=None):
        chr = self.chr()
        if (outer is True):
            car = self.outer_car()
            signature = self.outer_signature()
            body = self.cert().data()
            body = ASN1().add_tag(0x7f21, body).add_tag(0x42, car).encode()
        else:
            car = self.car()
            signature = self.signature()
            body = self.body().data(return_tag=True)
        if ((car != chr or outer is True) and dica is None):
            try:
                with open(os.path.join(cert_dir,bytes(car)), 'rb') as f:
                    dica = f.read()
            except FileNotFoundError:
                print(f'[Warning: File {car.decode()} not found]')
                return False
        if (dica is None):
            puk = self.pubkey().data()
        else:
            puk = CVC().decode(dica).pubkey().data()
        scheme = ASN1().decode(puk).oid()
        h,p = get_hash_padding(scheme)
        try:
            if (scheme_rsa(scheme)):
                pubkey = rsa.RSAPublicNumbers(ASN1().decode(puk).find(0x82).data(), ASN1().decode(puk).find(0x81).data()).public_key()
                pubkey.verify(signature, body, p, h)
            else:
                if (not curve):
                    curve = self.find_domain(cert_dir, outer)
                Q = ASN1().decode(puk).find(0x86).data()
                if (curve and Q):
                    pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve, bytes(Q))
                    pubkey.verify(utils.encode_dss_signature(int.from_bytes(signature[:len(signature)//2],'big'), int.from_bytes(signature[len(signature)//2:],'big')), body, ec.ECDSA(h))
                else:
                    return False
        except InvalidSignature:
            return False
        return True

    def find_domain(self, cert_dir='', outer=False):
        adata = self.encode()
        try:
            P = CVC().decode(adata).pubkey().find(0x81) if outer is False else None
            if (P):
                return find_curve(P.data())
            depth = 10
            while (P == None and depth > 0):
                car = CVC().decode(adata).outer_car()
                if (not car or outer is False):
                    car = CVC().decode(adata).car()
                chr = CVC().decode(adata).chr()
                with open(os.path.join(cert_dir,bytes(car)), 'rb') as f:
                    adata = f.read()
                    P = CVC().decode(adata).pubkey().find(0x81)
                if (P):
                    return find_curve(P.data())
                depth -= 1
        except FileNotFoundError:
            print(f'[Warning: File {car.decode()} not found]')
        return None
