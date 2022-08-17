#!/usr/bin/env python3
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

import argparse, logging
from cvc import CVC
from binascii import hexlify
from utils import scheme_rsa, get_hash_padding
from oid import oid2scheme
import oid
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from ec_curves import find_curve
from asn1 import ASN1
from datetime import date

logger = logging.getLogger(__name__)   

def parse_args():
    parser = argparse.ArgumentParser(description='Prints a Card Verifiable Certificate')
    parser.add_argument('file',help='Certificate to print', metavar='FILENAME')
    args = parser.parse_args()
    
    return args

def bcd2date(v):
    return date(v[0]*10+v[1]+2000, v[2]*10+v[3], v[4]*10+v[5])

def main(args):
    with open(args.file, 'rb') as f:
        cdata = f.read()
        
    print('Certificate:')
    print(f'  Profile Identifier: {hexlify(CVC().decode(cdata).cpi()).decode()}')
    print(f'  CAR: {(CVC().decode(cdata).car()).decode()}')
    print('  Public Key:')
    puboid = CVC().decode(cdata).pubkey().oid()
    print(f'    Scheme: {oid2scheme(puboid)}')
    pubkey = None
    scheme = puboid
    if (scheme_rsa(puboid)):
        pubkey = rsa.RSAPublicNumbers(CVC().decode(cdata).pubkey().find(0x82).data(), CVC().decode(cdata).pubkey().find(0x81).data()).public_key()
        print(f'    Modulus: {hexlify(pubkey.public_numbers().n)}')
        print(f'    Exponent: {hexlify(pubkey.public_numbers().e)}')
    else:
        P = None
        if (CVC().decode(cdata).pubkey().find(0x81)):
            P = CVC().decode(cdata).pubkey().find(0x81).data()
            curve = find_curve(P)
            Q = CVC().decode(cdata).pubkey().find(0x86).data()
            pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve, Q)
        else:
            adata = cdata
            scheme = None
            Q = None
            while (P == None):
                car = CVC().decode(adata).car()
                with open(car, 'rb') as f:
                    adata = f.read()
                    P = CVC().decode(adata).pubkey().find(0x81)
                    if (scheme == None):
                        scheme = CVC().decode(adata).pubkey().oid()
                    if (Q == None):
                        Q = CVC().decode(adata).pubkey().find(0x86).data()
            if (P):
                P = P.data()
                curve = find_curve(P)
                pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve, Q)
        print(f'    Public Point: {hexlify(CVC().decode(cdata).pubkey().find(0x86).data()).decode()}')
    print(f'  CHR: {(CVC().decode(cdata).chr()).decode()}')
    role = CVC().decode(cdata).role()
    if (role):
        print('  CHAT:')
        o = role.oid()
        if (o == oid.ID_IS):
            print('    Role: TypeIS')
        elif (o == oid.ID_AT):
            print('    Role: TypeAT')
        elif (o == oid.ID_ST):
            print('    Role: TypeST')
        print(f'    Bytes: {hexlify(CVC().decode(cdata).role().find(0x53).data()).decode()}')
        print(f'  Since: {bcd2date(CVC().decode(cdata).valid()).strftime("%Y-%m-%d")}')
        print(f'  Expires: {bcd2date(CVC().decode(cdata).expires()).strftime("%Y-%m-%d")}')
    signature = CVC().decode(cdata).signature()
    body = CVC().decode(cdata).body().data()
    body = ASN1().add_tag(0x7f4e, body).encode()
    if (pubkey):
        h,p = get_hash_padding(scheme)
        try:
            if (scheme_rsa(puboid)):
                pubkey.verify(signature, body, p, h)
            else:
                pubkey.verify(utils.encode_dss_signature(int.from_bytes(signature[:len(signature)//2],'big'), int.from_bytes(signature[len(signature)//2:],'big')), body, ec.ECDSA(h))
            print('Inner signature is VALID')
        except InvalidSignature:
            print('Inner signature is NOT VALID')
            
    

if __name__ == "__main__":
    args = parse_args()
    main(args)
    