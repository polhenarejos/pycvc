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

from terminal import TypeIS, TypeAT, TypeST, Type
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cvc import CVC
from asn1 import ASN1
import oid

if __name__ == "__main__":
    from binascii import hexlify
    priv_key = ec.generate_private_key(ec.SECP192R1())
    #priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = CVC().req(priv_key.public_key(), oid.ID_TA_ECDSA_SHA_256, priv_key, oid.ID_TA_ECDSA_SHA_256, b"HSMCVCA", b"HSMCVCA", b"HSMCVCA", priv_key)

#    cert = CVC().cert(priv_key.public_key(), priv_key, b"HSMCVCA", b"HSMCVCA", TypeAT(Type.CVCA), 10)
    data = cert.encode()
    print(hexlify(data))
    
    with open("test.cvcert", "wb") as file:
        file.write(data)
    
    for tup in ASN1().decode(data).all():
        print(f'{hex(tup[0])} ({len(tup[1])}): {hexlify(tup[1])}')
        
    print(hexlify(ASN1().decode(data).find(0x7f21).find(0x7f4e).find(0x5f20).data()))
    
    