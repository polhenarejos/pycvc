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
from utils import scheme_rsa, scheme_ecdsa, from_bcd
from oid import oid2scheme
import oid

logger = logging.getLogger(__name__)   

def parse_args():
    parser = argparse.ArgumentParser(description='Prints a Card Verifiable Certificate')
    parser.add_argument('file',help='Certificate to print', metavar='FILENAME')
    args = parser.parse_args()
    
    return args

def main(args):
    with open(args.file, 'rb') as f:
        cdata = f.read()
        
    print('Certificate:')
    print(f'  Profile Identifier: {hexlify(CVC().decode(cdata).cpi()).decode()}')
    print(f'  CAR: {(CVC().decode(cdata).car()).decode()}')
    print('  Public Key:')
    puboid = CVC().decode(cdata).pubkey().oid()
    print(f'    Scheme: {oid2scheme(puboid)}')
    if (scheme_rsa(puboid)):
        print(f'    Modulus: {hexlify(CVC().decode(cdata).pubkey().find(0x81).data())}')
        print(f'    Exponent: {hexlify(CVC().decode(cdata).pubkey().find(0x82).data())}')
    else:
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
        print(f'  Expires: {from_bcd(CVC().decode(cdata).expires())}')
        print(f'  Since: {from_bcd(CVC().decode(cdata).valid())}')

if __name__ == "__main__":
    args = parse_args()
    main(args)
    