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
from cvc.utils import scheme_rsa, scheme_eddsa
from cvc.oid import oid2scheme
from cvc import __version__, oid
from datetime import date
import os

logger = logging.getLogger(__name__)
cert_dir = b''

# Authorization bits according to
# BSI-TR-03110-4 Chapter 2.2.3.2 Table 4
AuthorizationBits = {
    "Upper Role Bit": 39,
    "Lower Role Bit": 38,
    "Write Datagroup 17": 37,
    "Write Datagroup 18": 36,
    "Write Datagroup 19": 35,
    "Write Datagroup 20": 34,
    "Write Datagroup 21": 33,
    "Write Datagroup 22": 32,
    "RFU": 31,
    "PSA": 30,
    "Read Datagroup 22": 29,
    "Read Datagroup 21": 28,
    "Read Datagroup 20": 27,
    "Read Datagroup 19": 26,
    "Read Datagroup 18": 25,
    "Read Datagroup 17": 24,
    "Read Datagroup 16": 23,
    "Read Datagroup 15": 22,
    "Read Datagroup 14": 21,
    "Read Datagroup 13": 20,
    "Read Datagroup 12": 19,
    "Read Datagroup 11": 18,
    "Read Datagroup 10": 17,
    "Read Datagroup 09": 16,
    "Read Datagroup 08": 15,
    "Read Datagroup 07": 14,
    "Read Datagroup 06": 13,
    "Read Datagroup 05": 12,
    "Read Datagroup 04": 11,
    "Read Datagroup 03": 10,
    "Read Datagroup 02": 9,
    "Read Datagroup 01": 8,
    "Install Qualified Certificate": 7,
    "Install Certificate": 6,
    "PIN Management": 5,
    "CAN allowed": 4,
    "Privileged Terminal": 3,
    "Restricted Identification": 2,
    "Municipality ID Verification": 1,
    "Age Verification": 0,
}

def parse_args():
    global cert_dir
    parser = argparse.ArgumentParser(description='Prints a Card Verifiable Certificate')
    parser.add_argument('--version', help='Displays the current version', action='store_true')
    parser.add_argument('file',help='Certificate to print', metavar='FILENAME')
    parser.add_argument('-d','--directory', help='Directory where chain CV certificates are located', metavar='DIRECTORY')
    parser.add_argument('--print-bits', help='Print a detailed info about Authorization bits set',action='store_true')
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
    print("ARGS",args)
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
    elif (scheme_eddsa(puboid)):
        print(f'    Public Point: {hexlify(CVC().decode(cdata).pubkey().find(0x84).data()).decode()}')
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
        if(args.print_bits):
            bits = CVC().decode(cdata).decode_authorization_bits()
            for bit in AuthorizationBits:
                print(
                    "        Field '{:<32}' has value: {:^6} at offset: {:2}".format(
                        bit,
                        str(bits[AuthorizationBits[bit]] == "1"),
                        AuthorizationBits[bit],
                    )
                )
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
