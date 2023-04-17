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

import argparse, logging, sys
from cvc.certificates import CVC
from binascii import hexlify
from cvc.utils import scheme_rsa
from cvc.oid import oid2scheme
from cvc import __version__, oid
from datetime import date
import os

logger = logging.getLogger(__name__)
cert_dir = b''

def parse_args():
    global cert_dir
    parser = argparse.ArgumentParser(description='Prints a Card Verifiable Certificate')
    parser.add_argument('--version', help='Displays the current version', action='store_true')
    parser.add_argument('file',help='Certificate to print', metavar='FILENAME')
    parser.add_argument('-d','--directory', help='Directory where chain CV certificates are located', metavar='DIRECTORY')
    if ('--version' in sys.argv):
        print('Card Verifiable Certificate tools for Python')
        print('Author: Pol Henarejos')
        print(f'Version {__version__}')
        print('')
        print('Report bugs to http://github.com/polhenarejos/pycvc/issues')
        print('')
        sys.exit(0)
    args = parser.parse_args()
    if (args.directory):
        cert_dir = args.directory.encode()
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
    isreq = CVC().decode(cdata).is_req()
    if (CVC().decode(cdata).verify(cert_dir=cert_dir, dica=cdata if isreq else None)):
        print('Inner signature is VALID')
        ret = True
    else:
        print('Inner signature is NOT VALID')
        ret = False
    if (car != chr):
        if (isreq):
            ret = CVC().decode(cdata).verify(cert_dir=cert_dir, dica=cdata)
        else:
            try:
                while (car != chr):
                    with open(os.path.join(cert_dir,bytes(car)), 'rb') as f:
                        adata = f.read()
                        ret = ret and CVC().decode(adata).verify(cert_dir=cert_dir)
                        chr = CVC().decode(adata).chr()
                        car = CVC().decode(adata).car()
            except FileNotFoundError:
                print(f'[Warning: File {car.decode()} not found]')
                ret = False
    else:
        if (isreq):
            print(f'Outer CAR: {CVC().decode(cdata).outer_car().decode()}')
            outret = CVC().decode(cdata).verify(cert_dir=cert_dir, outer=True)
            if (outret):
                print('Outer signature is VALID')
            else:
                print('Outer signature is NOT VALID')
            ret = ret and outret

    if (ret):
        print('Certificate VALID')
    else:
        print('Certificate NOT VALID')

def run():
    args = parse_args()
    main(args)

if __name__ == "__main__":
    run()
