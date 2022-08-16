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

BSI_DE                      = b"\x04\x00\x7F\x00\x07"

ID_CA                       = BSI_DE + b"\x02\x02\x03"

ID_CA_DH                    = ID_CA + b"\x01"

ID_CA_DH_3DES_CBC_CBC       = ID_CA_DH + b"\x01"
ID_CA_DH_AES_CBC_CMAC_128   = ID_CA_DH + b"\x02"
ID_CA_DH_AES_CBC_CMAC_192   = ID_CA_DH + b"\x03"
ID_CA_DH_AES_CBC_CMAC_256   = ID_CA_DH + b"\x04"

ID_CA_ECDH                  = ID_CA+ b"\x02"

ID_CA_ECDH_3DES_CBC_CBC     = ID_CA_ECDH + b"\x01"
ID_CA_ECDH_AES_CBC_CMAC_128 = ID_CA_ECDH + b"\x02"
ID_CA_ECDH_AES_CBC_CMAC_192 = ID_CA_ECDH + b"\x03"
ID_CA_ECDH_AES_CBC_CMAC_256 = ID_CA_ECDH + b"\x04"

ID_PK                       = BSI_DE + b"\x02\x02\0x1"
ID_PK_DH                    = ID_PK + b"\x01"
ID_PK_ECDH                  = ID_PK + b"\x02"

ID_TA                       = BSI_DE + b"\x02\x02\x02"

ID_TA_RSA                   = ID_TA + b"\x01"

ID_TA_RSA_V1_5_SHA_1        = ID_TA_RSA + b"\x01"
ID_TA_RSA_V1_5_SHA_256      = ID_TA_RSA + b"\x02"
ID_TA_RSA_PSS_SHA_1         = ID_TA_RSA + b"\x03"
ID_TA_RSA_PSS_SHA_256       = ID_TA_RSA + b"\x04"
ID_TA_RSA_V1_5_SHA_512      = ID_TA_RSA + b"\x05"
ID_TA_RSA_PSS_SHA_512       = ID_TA_RSA + b"\x06"

ID_TA_ECDSA                 = ID_TA + b"\x02"

ID_TA_ECDSA_SHA_1           = ID_TA_ECDSA + b"\x01"
ID_TA_ECDSA_SHA_224         = ID_TA_ECDSA + b"\x02"
ID_TA_ECDSA_SHA_256         = ID_TA_ECDSA + b"\x03"
ID_TA_ECDSA_SHA_384         = ID_TA_ECDSA + b"\x04"
ID_TA_ECDSA_SHA_512         = ID_TA_ECDSA + b"\x05"

ID_RI                       = BSI_DE + b"\x02\x02\x05"

ID_RI_DH                    = ID_RI + b"\x01"

ID_RI_DH_SHA_1              = ID_RI_DH + b"\x01"
ID_RI_DH_SHA_224            = ID_RI_DH + b"\x02"
ID_RI_DH_SHA_256            = ID_RI_DH + b"\x03"

ID_RI_ECDH                  = ID_RI + b"\x02" 

ID_RI_ECDH_SHA_1            = ID_RI_ECDH + b"\x01"
ID_RI_ECDH_SHA_224          = ID_RI_ECDH + b"\x02"
ID_RI_ECDH_SHA_256          = ID_RI_ECDH + b"\x03"

ID_CI                       = BSI_DE + b"\x02\x02\x06"

ID_ROLES                    = BSI_DE + b"\x03\x01\x02"
ID_IS                       = ID_ROLES + b"\x01"
ID_AT                       = ID_ROLES + b"\x02"
ID_ST                       = ID_ROLES + b"\x03"

