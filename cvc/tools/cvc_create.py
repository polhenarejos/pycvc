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
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448
from cryptography.hazmat.primitives import serialization
from cvc.terminal import Type, TypeIS, TypeAT, TypeST
from cvc.certificates import CVC
from cvc.utils import scheme_rsa, scheme_eddsa
from cvc import __version__, oid

logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description='Generate a Card Verifiable Certificate')
    parser.add_argument('--version', help='Displays the current version', action='store_true')
    parser.add_argument('-o','--out-cert', help='Generated certificate file', metavar='FILENAME')
    parser.add_argument('-r','--role', help='The role of entity', choices=['cvca','dv_domestic','dv_foreign','terminal'])
    parser.add_argument('-t','--type', help='The type of terminal. If not provided, it creates a certificate request', choices=['at','is','st'])
    parser.add_argument('--days', help='Days of validity since today (or since --since)', default=90)
    parser.add_argument('--since', help='Certificate effective date (use with caution) [in YYMMDD format]', metavar='YYMMDD')
    parser.add_argument('-k','--sign-key', help='Private key to sign the certificate.', required=True, metavar='FILENAME')
    parser.add_argument('--sign-as', help='CV certificate of signing entity. If not provided, the certificate is self-signed [generates a certificate]', metavar='FILENAME')
    parser.add_argument('--outer-as', help='Outer certificate for CV request', metavar='FILENAME')
    parser.add_argument('--outer-key', help='Private key for outer signature of CV request', metavar='FILENAME')
    parser.add_argument('-p','--public-key', help='The public key contained in the certificate. If not provided, it is derived from the sign-key', metavar='FILENAME')
    parser.add_argument('-q','--request', help='Generates a certificate based on a request', metavar='FILENAME')
    parser.add_argument('--out-key', help='File to store the generated private key [default CHR.pkcs8]', metavar='FILENAME')
    parser.add_argument('-s','--scheme', help='Signature scheme', choices=["ECDSA_SHA_1",
                               "ECDSA_SHA_224", "ECDSA_SHA_256",
                               "ECDSA_SHA_384", "ECDSA_SHA_512",
                               "RSA_v1_5_SHA_1", "RSA_v1_5_SHA_256",
                               "RSA_v1_5_SHA_512", "RSA_PSS_SHA_1",
                               "RSA_PSS_SHA_256", "RSA_PSS_SHA_512"])
    parser.add_argument('-c','--chr', help='Certificate Holder Reference')
    parser.add_argument('-a','--req-car', help='Certificate Authority Reference expected for CV request [generates a request]')
    parser.add_argument('--chat', help='CHAT bits for terminal (binary base)', metavar='BITS')
    parser.add_argument('--write-dg17', help='Allow writing DG 17 (Normal Place of Residence)', action='store_true')
    parser.add_argument('--write-dg18', help='Allow writing DG 18 (Community ID)', action='store_true')
    parser.add_argument('--write-dg19', help='Allow writing DG 19 (Residence Permit I)', action='store_true')
    parser.add_argument('--write-dg20', help='Allow writing DG 20 (Residence Permit II)', action='store_true')
    parser.add_argument('--write-dg21', help='Allow writing DG 21 (Optional Data)', action='store_true')
    parser.add_argument('--write-dg22', help='Allow writing DG 22 (Email address)', action='store_true')
    parser.add_argument('--rfu31', help='Allow RFU R/W Access bit 31', action='store_true')
    parser.add_argument('--psa', help='Allow PSA', action='store_true')
    parser.add_argument('--read-dg1', help='Allow reading DG 1   (Document Type)', action='store_true')
    parser.add_argument('--read-dg2', help='Allow reading DG 2   (Issuing State)', action='store_true')
    parser.add_argument('--read-dg3', help='Allow reading DG 3   (Date of Expiry)', action='store_true')
    parser.add_argument('--read-dg4', help='Allow reading DG 4   (Given Names)', action='store_true')
    parser.add_argument('--read-dg5', help='Allow reading DG 5   (Family Names)', action='store_true')
    parser.add_argument('--read-dg6', help='Allow reading DG 6   (Religious/Artistic Name)', action='store_true')
    parser.add_argument('--read-dg7', help='Allow reading DG 7   (Academic Title)', action='store_true')
    parser.add_argument('--read-dg8', help='Allow reading DG 8   (Date of Birth)', action='store_true')
    parser.add_argument('--read-dg9', help='Allow reading DG 9   (Place of Birth)', action='store_true')
    parser.add_argument('--read-dg10', help='Allow reading DG 10  (Nationality)', action='store_true')
    parser.add_argument('--read-dg11', help='Allow reading DG 11  (Sex)', action='store_true')
    parser.add_argument('--read-dg12', help='Allow reading DG 12  (Optional Data)', action='store_true')
    parser.add_argument('--read-dg13', help='Allow reading DG 13  (Birth Name)', action='store_true')
    parser.add_argument('--read-dg14', help='Allow reading DG 14  (Written Signature)', action='store_true')
    parser.add_argument('--read-dg15', help='Allow reading DG 15  (Date of Issuance)', action='store_true')
    parser.add_argument('--read-dg16', help='Allow reading DG 16', action='store_true')
    parser.add_argument('--read-dg17', help='Allow reading DG 17  (Normal Place of Residence)', action='store_true')
    parser.add_argument('--read-dg18', help='Allow reading DG 18  (Community ID)', action='store_true')
    parser.add_argument('--read-dg19', help='Allow reading DG 19  (Residence Permit I)', action='store_true')
    parser.add_argument('--read-dg20', help='Allow reading DG 20  (Residence Permit II)', action='store_true')
    parser.add_argument('--read-dg21', help='Allow reading DG 21  (Phone Number)', action='store_true')
    parser.add_argument('--read-dg22', help='Allow reading DG 22  (Email Address)', action='store_true')
    parser.add_argument('--install-qual-cert', help='Allow installing qualified certificate', action='store_true')
    parser.add_argument('--install-cert', help='Allow installing certificate', action='store_true')
    parser.add_argument('--pin-management ', help='Allow PIN management', action='store_true')
    parser.add_argument('--can-allowed', help='CAN allowed', action='store_true')
    parser.add_argument('--privileged ', help='Privileged terminal', action='store_true')
    parser.add_argument('--rid', help='Allow restricted identification', action='store_true')
    parser.add_argument('--verify-community', help='Allow community ID verification', action='store_true')
    parser.add_argument('--verify-age', help='Allow age verification', action='store_true')

    parser.add_argument('--rfu5', help='Allow RFU bit 5', action='store_true')
    parser.add_argument('--rfu4', help='Allow RFU bit 4', action='store_true')
    parser.add_argument('--rfu3', help='Allow RFU bit 3', action='store_true')
    parser.add_argument('--rfu2', help='Allow RFU bit 2', action='store_true')
    parser.add_argument('--gen-qual-sig', help='Allow generated qualified electronic signature', action='store_true')
    parser.add_argument('--gen-sig', help='Allow generated electronic signature', action='store_true')

    parser.add_argument('--read-iris', help='Read access to ePassport application: DG 4 (Iris)', action='store_true')
    parser.add_argument('--read-fingerprint', help='Read access to ePassport application: DG 3 (Fingerprint)', action='store_true')

    if ('--version' in sys.argv):
        print('Card Verifiable Certificate tools for Python')
        print('Author: Pol Henarejos')
        print(f'Version {__version__}')
        print('')
        print('Report bugs to http://github.com/polhenarejos/pycvc/issues')
        print('')
        sys.exit(0)

    args = parser.parse_args()
    return args

def load_private_key(filename):
    with open(filename, 'rb') as f:
        p8data = f.read()
        try:
            return serialization.load_der_private_key(p8data,password=None)
        except ValueError:
            return serialization.load_pem_private_key(p8data,password=None)
    return None

def get_role(r):
    if (r == 'cvca'):
        return Type.CVCA
    elif (r== 'dv_domestic'):
        return Type.DV_domestic
    elif (r == 'dv_foreign'):
        return Type.DV_foreign
    elif (r == 'terminal'):
        return Type.Terminal
    return None

def get_type(t, role, args):
    if (t == 'at'):
        typ = TypeAT(role)
    elif (t == 'st'):
        typ = TypeST(role)
    elif (t == 'is'):
        typ = TypeIS(role)
    else:
        return None

    for attr in typ._args:
        setattr(typ, attr, getattr(args, attr, 0))

    return typ

def parse_as(a):
    with open(a, 'rb') as f:
        cadata = f.read()
        chr = CVC().decode(cadata).chr()
        scheme = CVC().decode(cadata).pubkey().oid()
        return chr,scheme
    return None

def main(args):
    sign_key = load_private_key(args.sign_key)
    puboid = None
    chr = None
    if (args.public_key):
        with open(args.public_key, 'rb') as f:
            pubdata = f.read()
            try:
                pub_key = serialization.load_der_public_key(pubdata)
            except ValueError:
                pub_key = serialization.load_pem_public_key(pubdata)
    elif (args.request):
        with open(args.request, 'rb') as f:
            data = f.read()
            puboid = CVC().decode(data).pubkey().oid()
            chr = CVC().decode(data).chr()
            if (scheme_rsa(puboid)):
                pub_key = rsa.RSAPublicNumbers(int.from_bytes(CVC().decode(data).pubkey().find(0x82).data(), 'big'), int.from_bytes(CVC().decode(data).pubkey().find(0x81).data(), 'big')).public_key()
            elif (scheme_eddsa(puboid)):
                Q = CVC().decode(data).pubkey().find(0x84).data()
                if (len(Q) == 32):
                    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes(Q))
                else:
                    pub_key = ed448.Ed448PublicKey.from_public_bytes(bytes(Q))
            else:
                curve = CVC().decode(data).find_domain()
                Q = CVC().decode(data).pubkey().find(0x86).data()
                pub_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, bytes(Q))
    else:
        if (args.sign_as and args.type and not args.outer_as and not args.outer_key):
            if (isinstance(sign_key, rsa.RSAPrivateKey)):
                priv_key = rsa.generate_private_key(key_size=sign_key.key_size, public_exponent=65537)
            elif (isinstance(sign_key, ec.EllipticCurvePrivateKey)):
                priv_key = ec.generate_private_key(sign_key.curve)
            pub_key = priv_key.public_key()
            with open(args.out_key if args.out_key != None else args.chr+'.pkcs8','wb') as f:
                der = priv_key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
                f.write(der)
        else:
            pub_key = sign_key.public_key()

    role = get_role(args.role)

    typ = get_type(args.type, role, args)

    if (typ):
        typ.chat(args.chat)

    if (not puboid):
        puboid = oid.scheme2oid(args.scheme)
    if (not puboid):
        if (isinstance(pub_key, rsa.RSAPublicKey)):
            puboid = oid.ID_TA_RSA_PSS_SHA256
        elif (isinstance(pub_key, ec.EllipticCurvePublicKey)):
            puboid = oid.ID_TA_ECDSA_SHA_256
    if (isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey))):
        puboid = oid.ID_RI_ECDH_SHA_256

    if (args.sign_as and typ and not args.outer_as and not args.outer_key): # Cert
        car, signscheme = parse_as(args.sign_as)
    else: # Req
        if (args.req_car):
            car = args.req_car.encode()
        else:
            car = args.chr.encode()
        signscheme = puboid

    if (not chr):
        chr = args.chr.encode()
    if (args.req_car or (args.outer_as and args.outer_key)):
        if (args.outer_as and args.outer_key):
            outercar, outerscheme = parse_as(args.outer_as)
            outerkey = load_private_key(args.outer_key)
        else:
            outercar,outerscheme,outerkey = None,None,None
        cert = CVC().req(pub_key, puboid, sign_key, signscheme, car=car, chr=chr, outercar=outercar, outerkey=outerkey, outerscheme=outerscheme)
        ext = 'cvreq'
    else:
        cert = CVC().cert(pub_key, puboid, sign_key, signscheme, car=car, chr=chr, role=typ, days=args.days if typ else None, since=args.since if typ else None)
        ext = 'cvcert'

    with open(args.out_cert if args.out_cert != None else chr.decode()+'.'+ext,'wb') as f:
        f.write(cert.encode())

def run():
    args = parse_args()
    main(args)

if __name__ == "__main__":
    run()