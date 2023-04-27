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

from cryptography.hazmat.primitives.asymmetric import ec
from binascii import unhexlify

class SECP192R1:
    P = bytearray(unhexlify('fffffffffffffffffffffffffffffffeffffffffffffffff'))
    A = bytearray(unhexlify('fffffffffffffffffffffffffffffffefffffffffffffffc'))
    B = bytearray(unhexlify('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'))
    G = bytearray(unhexlify('04188da80eb03090f67cbf20eb43a18800f4ff0afd82ff101207192b95ffc8da78631011ed6b24cdd573f977a11e794811'))
    O = bytearray(unhexlify('ffffffffffffffffffffffff99def836146bc9b1b4d22831'))
    F = bytearray(b"\x01")

class SECP224R1:
    P = bytearray(unhexlify('ffffffffffffffffffffffffffffffff000000000000000000000001'))
    A = bytearray(unhexlify('fffffffffffffffffffffffffffffffefffffffffffffffffffffffe'))
    B = bytearray(unhexlify('b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'))
    G = bytearray(unhexlify('04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'))
    O = bytearray(unhexlify('ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'))
    F = bytearray(b"\x01")

class SECP256R1:
    P = bytearray(unhexlify('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'))
    A = bytearray(unhexlify('ffffffff00000001000000000000000000000000fffffffffffffffffffffffc'))
    B = bytearray(unhexlify('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'))
    G = bytearray(unhexlify('046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'))
    O = bytearray(unhexlify('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'))
    F = bytearray(b"\x01")

class SECP384R1:
    P = bytearray(unhexlify('fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff'))
    A = bytearray(unhexlify('fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc'))
    B = bytearray(unhexlify('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef'))
    G = bytearray(unhexlify('04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'))
    O = bytearray(unhexlify('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'))
    F = bytearray(b"\x01")

class SECP521R1:
    P = bytearray(unhexlify('01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))
    A = bytearray(unhexlify('01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc'))
    B = bytearray(unhexlify('0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00'))
    G = bytearray(unhexlify('0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650'))
    O = bytearray(unhexlify('01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'))
    F = bytearray(b"\x01")

class BP192R1:
    P = bytearray(unhexlify('c302f41d932a36cda7a3463093d18db78fce476de1a86297'))
    A = bytearray(unhexlify('6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef'))
    B = bytearray(unhexlify('469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9'))
    G = bytearray(unhexlify('04c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd614b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f'))
    O = bytearray(unhexlify('c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1'))
    F = bytearray(b"\x01")

class BP224R1:
    P = bytearray(unhexlify('d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff'))
    A = bytearray(unhexlify('68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43'))
    B = bytearray(unhexlify('2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b'))
    G = bytearray(unhexlify('040d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd'))
    O = bytearray(unhexlify('d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f'))
    F = bytearray(b"\x01")

class BP256R1:
    P = bytearray(unhexlify('a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377'))
    A = bytearray(unhexlify('7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9'))
    B = bytearray(unhexlify('26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6'))
    G = bytearray(unhexlify('048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997'))
    O = bytearray(unhexlify('a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7'))
    F = bytearray(b"\x01")

class BP320R1:
    P = bytearray(unhexlify('d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27'))
    A = bytearray(unhexlify('3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4'))
    B = bytearray(unhexlify('520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6'))
    G = bytearray(unhexlify('0443bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e2061114fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1'))
    O = bytearray(unhexlify('d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311'))
    F = bytearray(b"\x01")

class BP384R1:
    P = bytearray(unhexlify('8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53'))
    A = bytearray(unhexlify('7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826'))
    B = bytearray(unhexlify('04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11'))
    G = bytearray(unhexlify('041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315'))
    O = bytearray(unhexlify('8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565'))
    F = bytearray(b"\x01")

class BP512R1:
    P = bytearray(unhexlify('aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3'))
    A = bytearray(unhexlify('7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca'))
    B = bytearray(unhexlify('3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723'))
    G = bytearray(unhexlify('0481aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f8227dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892'))
    O = bytearray(unhexlify('aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069'))
    F = bytearray(b"\x01")

class SECP192K1:
    P = bytearray(unhexlify('fffffffffffffffffffffffffffffffffffffffeffffee37'))
    A = bytearray(unhexlify('000000000000000000000000000000000000000000000000'))
    B = bytearray(unhexlify('000000000000000000000000000000000000000000000003'))
    G = bytearray(unhexlify('04db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d'))
    O = bytearray(unhexlify('fffffffffffffffffffffffe26f2fc170f69466a74defd8d'))
    F = bytearray(b"\x01")

class SECP224K1:
    P = bytearray(unhexlify('fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d'))
    A = bytearray(unhexlify('00000000000000000000000000000000000000000000000000000000'))
    B = bytearray(unhexlify('00000000000000000000000000000000000000000000000000000005'))
    G = bytearray(unhexlify('04a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5'))
    O = bytearray(unhexlify('010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7'))
    F = bytearray(b"\x01")

class SECP256K1:
    P = bytearray(unhexlify('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'))
    A = bytearray(unhexlify('0000000000000000000000000000000000000000000000000000000000000000'))
    B = bytearray(unhexlify('0000000000000000000000000000000000000000000000000000000000000007'))
    G = bytearray(unhexlify('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'))
    O = bytearray(unhexlify('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'))
    F = bytearray(b"\x01")

def ec_domain(curve):
    if (curve.name == 'secp192r1'):
        return SECP192R1()
    elif (curve.name == 'secp256r1'):
        return SECP256R1()
    elif (curve.name == 'secp384r1'):
        return SECP384R1()
    elif (curve.name == 'secp521r1'):
        return SECP521R1()
    elif (curve.name == 'brainpoolP192r1'):
        return BP192R1()
    elif (curve.name == 'brainpoolP224r1'):
        return BP224R1()
    elif (curve.name == 'brainpoolP256r1'):
        return BP256R1()
    elif (curve.name == 'brainpoolP320r1'):
        return BP320R1()
    elif (curve.name == 'brainpoolP384r1'):
        return BP384R1()
    elif (curve.name == 'brainpoolP512r1'):
        return BP512R1()
    elif (curve.name == 'secp192k1'):
        return SECP192K1()
    elif (curve.name == 'secp256k1'):
        return SECP256K1()
    return None

def find_curve(P):
    if (SECP192R1.P == P):
        return ec.SECP192R1()
    elif (SECP256K1.P == P):
        return ec.SECP256K1()
    elif (SECP256R1.P == P):
        return ec.SECP256R1()
    elif (SECP384R1.P == P):
        return ec.SECP384R1()
    elif (SECP521R1.P == P):
        return ec.SECP521R1()
    elif (BP256R1.P == P):
        return ec.BrainpoolP256R1()
    elif (BP384R1.P == P):
        return ec.BrainpoolP384R1()
    elif (BP512R1.P == P):
        return ec.BrainpoolP512R1()
    return None
