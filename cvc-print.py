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
from cryptography.hazmat.primitives.asymmetric import rsa, ec, utils
from cryptography.exceptions import InvalidSignature
from ec_curves import find_curve
from asn1 import ASN1
from datetime import date
import os

logger = logging.getLogger(__name__)   
cert_dir = b''

def parse_args():
    global cert_dir
    parser = argparse.ArgumentParser(description='Prints a Card Verifiable Certificate')
    parser.add_argument('file',help='Certificate to print', metavar='FILENAME')
    parser.add_argument('-d','--directory', help='Directory where chain CV certificates are located', metavar='DIRECTORY')
    args = parser.parse_args()
    if (args.directory):
        cert_dir = args.directory.encode()
    return args

def bcd2date(v):
    return date(v[0]*10+v[1]+2000, v[2]*10+v[3], v[4]*10+v[5])

def find_domain(adata):
    try:
        P = CVC().decode(adata).pubkey().find(0x81)
        while (P == None):
            car = CVC().decode(adata).car()
            chr = CVC().decode(adata).chr()
            with open(os.path.join(cert_dir,car), 'rb') as f:
                adata = f.read()
                P = CVC().decode(adata).pubkey().find(0x81)
            if (car == chr):
                break
        if (P):
            return find_curve(P.data())
    except FileNotFoundError:
        print(f'[Warning: File {car.decode()} not found]')
    return None

def verify(adata, outer = False):
    chr = CVC().decode(adata).chr()
    
    if (outer == True):
        car = CVC().decode(adata).outer_car()
        signature = CVC().decode(adata).outer_signature()
        body = CVC().decode(adata).cert().data()
        body = ASN1().add_tag(0x7f21, body).add_tag(0x42, car).encode()
    else:
        car = CVC().decode(adata).car()
        signature = CVC().decode(adata).signature()
        body = CVC().decode(adata).body().data()
        body = ASN1().add_tag(0x7f4e, body).encode()
    if (car != chr):
        try:
            with open(os.path.join(cert_dir,car), 'rb') as f:
                adata = f.read()
        except FileNotFoundError:
            print(f'[Warning: File {car.decode()} not found]')
            return False
    scheme = CVC().decode(adata).pubkey().oid()
    h,p = get_hash_padding(scheme)
    try:
        if (scheme_rsa(scheme)):
            pubkey = rsa.RSAPublicNumbers(CVC().decode(adata).pubkey().find(0x82).data(), CVC().decode(adata).pubkey().find(0x81).data()).public_key()
            pubkey.verify(signature, body, p, h)
        else:
            curve = find_domain(adata)
            Q = CVC().decode(adata).pubkey().find(0x86).data()
            if (curve and Q):
                pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve, Q)
                pubkey.verify(utils.encode_dss_signature(int.from_bytes(signature[:len(signature)//2],'big'), int.from_bytes(signature[len(signature)//2:],'big')), body, ec.ECDSA(h))
            else:
                return False
    except InvalidSignature:
        return False
    return True

def main(args):
    with open(args.file, 'rb') as f:
        cdata = f.read()
        
    print('Certificate:')
    print(f'  Profile Identifier: {hexlify(CVC().decode(cdata).cpi()).decode()}')
    print(f'  CAR: {(CVC().decode(cdata).car()).decode()}')
    print('  Public Key:')
    puboid = CVC().decode(cdata).pubkey().oid()
    print(f'    Scheme: {oid2scheme(puboid)}')
    chr = CVC().decode(cdata).chr()
    car = CVC().decode(cdata).car()
    if (scheme_rsa(puboid)):
        print(f'    Modulus: {hexlify(CVC().decode(cdata).pubkey().find(0x81).data()).decode()}')
        print(f'    Exponent: {hexlify(CVC().decode(cdata).pubkey().find(0x82).data()).decode()}')
    else:
        print(f'    Public Point: {hexlify(CVC().decode(cdata).pubkey().find(0x86).data()).decode()}')
    print(f'  CHR: {chr.decode()}')
    role = CVC().decode(cdata).role()
    if (role):
        print('  CHAT:')
        o = role.oid()
        if (o == oid.ID_IS):
            print('    Role:  TypeIS')
        elif (o == oid.ID_AT):
            print('    Role:  TypeAT')
        elif (o == oid.ID_ST):
            print('    Role:  TypeST')
        print(f'    Bytes: {hexlify(CVC().decode(cdata).role().find(0x53).data()).decode()}')
        print(f'  Since:   {bcd2date(CVC().decode(cdata).valid()).strftime("%Y-%m-%d")}')
        print(f'  Expires: {bcd2date(CVC().decode(cdata).expires()).strftime("%Y-%m-%d")}')
    if (verify(cdata)):
        print('Inner signature is VALID')
        ret = True
    else:
        print('Inner signature is NOT VALID')
        ret = False
    if (car != chr):
        try:
            while (car != chr):
                with open(os.path.join(cert_dir,car), 'rb') as f:
                    adata = f.read()
                    ret = ret and verify(adata)
                    chr = CVC().decode(adata).chr()
                    car = CVC().decode(adata).car()
        except FileNotFoundError:
            print(f'[Warning: File {car.decode()} not found]')
            ret = False
    else:
        isreq = CVC().decode(cdata).is_req()
        if (isreq):
            outret = verify(cdata, outer=True)
            if (outret):
                print('Outer signature is VALID')
            else:
                print('Outer signature is NOT VALID')
            ret = ret and outret
            
    if (ret):
        print('Certificate VALID')
    else:
        print('Certificate NOT VALID')

if __name__ == "__main__":
    args = parse_args()
    main(args)
    