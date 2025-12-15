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

ID_ECPSPUBLICKEY            = BSI_DE + b"\x01\x01\x02\x03"

ID_STANDARDIZED_DOMAIN_PARAMETERS = BSI_DE + b"\x01\x02"

ID_PK                       = BSI_DE + b"\x02\x02\x01"
ID_PK_DH                    = ID_PK + b"\x01"
ID_PK_ECDH                  = ID_PK + b"\x02"
ID_PS_PK                    = ID_PK + b"\x03"
ID_PS_PK_ECSCHNORR          = ID_PS_PK + b"\x02"

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

ID_CA                       = BSI_DE + b"\x02\x02\x03"

ID_CA_DH                    = ID_CA + b"\x01"
ID_CA_DH_3DES_CBC_CBC       = ID_CA_DH + b"\x01"
ID_CA_DH_AES_CBC_CMAC_128   = ID_CA_DH + b"\x02"
ID_CA_DH_AES_CBC_CMAC_192   = ID_CA_DH + b"\x03"
ID_CA_DH_AES_CBC_CMAC_256   = ID_CA_DH + b"\x04"

ID_CA_ECDH                  = ID_CA + b"\x02"
ID_CA_ECDH_3DES_CBC_CBC     = ID_CA_ECDH + b"\x01"
ID_CA_ECDH_AES_CBC_CMAC_128 = ID_CA_ECDH + b"\x02"
ID_CA_ECDH_AES_CBC_CMAC_192 = ID_CA_ECDH + b"\x03"
ID_CA_ECDH_AES_CBC_CMAC_256 = ID_CA_ECDH + b"\x04"

ID_PACE                     = BSI_DE + b"\x02\x02\x04"

ID_PACE_DH_GM               = ID_PACE + b"\x01"
ID_PACE_DH_GM_3DES_CBC_CBC  = ID_PACE_DH_GM + b"\x01"
ID_PACE_DH_GM_AES_CBC_CMAC_128  = ID_PACE_DH_GM + b"\x02"
ID_PACE_DH_GM_AES_CBC_CMAC_192  = ID_PACE_DH_GM + b"\x03"
ID_PACE_DH_GM_AES_CBC_CMAC_256  = ID_PACE_DH_GM + b"\x04"

ID_PACE_ECDH_GM               = ID_PACE + b"\x02"
ID_PACE_ECDH_GM_3DES_CBC_CBC  = ID_PACE_ECDH_GM + b"\x01"
ID_PACE_ECDH_GM_AES_CBC_CMAC_128  = ID_PACE_ECDH_GM + b"\x02"
ID_PACE_ECDH_GM_AES_CBC_CMAC_192  = ID_PACE_ECDH_GM + b"\x03"
ID_PACE_ECDH_GM_AES_CBC_CMAC_256  = ID_PACE_ECDH_GM + b"\x04"

ID_PACE_DH_IM               = ID_PACE + b"\x03"
ID_PACE_DH_IM_3DES_CBC_CBC  = ID_PACE_DH_IM + b"\x01"
ID_PACE_DH_IM_AES_CBC_CMAC_128  = ID_PACE_DH_IM + b"\x02"
ID_PACE_DH_IM_AES_CBC_CMAC_192  = ID_PACE_DH_IM + b"\x03"
ID_PACE_DH_IM_AES_CBC_CMAC_256  = ID_PACE_DH_IM + b"\x04"

ID_PACE_ECDH_IM               = ID_PACE + b"\x04"
ID_PACE_ECDH_IM_3DES_CBC_CBC  = ID_PACE_ECDH_IM + b"\x01"
ID_PACE_ECDH_IM_AES_CBC_CMAC_128  = ID_PACE_ECDH_IM + b"\x02"
ID_PACE_ECDH_IM_AES_CBC_CMAC_192  = ID_PACE_ECDH_IM + b"\x03"
ID_PACE_ECDH_IM_AES_CBC_CMAC_256  = ID_PACE_ECDH_IM + b"\x04"

ID_RI                       = BSI_DE + b"\x02\x02\x05"

ID_RI_DH                    = ID_RI + b"\x01"

ID_RI_DH_SHA_1              = ID_RI_DH + b"\x01"
ID_RI_DH_SHA_224            = ID_RI_DH + b"\x02"
ID_RI_DH_SHA_256            = ID_RI_DH + b"\x03"
ID_RI_DH_SHA_384            = ID_RI_DH + b"\x04"
ID_RI_DH_SHA_512            = ID_RI_DH + b"\x05"

ID_RI_ECDH                  = ID_RI + b"\x02"

ID_RI_ECDH_SHA_1            = ID_RI_ECDH + b"\x01"
ID_RI_ECDH_SHA_224          = ID_RI_ECDH + b"\x02"
ID_RI_ECDH_SHA_256          = ID_RI_ECDH + b"\x03"
ID_RI_ECDH_SHA_384          = ID_RI_ECDH + b"\x04"
ID_RI_ECDH_SHA_512          = ID_RI_ECDH + b"\x05"

ID_CI                       = BSI_DE + b"\x02\x02\x06"

ID_EIDSECURITY              = BSI_DE + b"\x02\x02\x07"

ID_PASSWORD_TYPE            = BSI_DE + b"\x02\x02\x08"

ID_PS                       = BSI_DE + b"\x02\x02\x0B"
ID_PSA                      = ID_PS + b"\x01"
ID_PSA_ECDH_ECSCHNORR       = ID_PSA + b"\x02"
ID_PSA_ECDH_ECSCHNORR_SHA256 = ID_PSA_ECDH_ECSCHNORR + b"\x03"
ID_PSA_ECDH_ECSCHNORR_SHA384 = ID_PSA_ECDH_ECSCHNORR + b"\x04"
ID_PSA_ECDH_ECSCHNORR_SHA512 = ID_PSA_ECDH_ECSCHNORR + b"\x05"

ID_PASSWORD_TYPE            = BSI_DE + b"\x02\x02\x0C"
ID_MRZ                      = ID_PASSWORD_TYPE + b"\x01"
ID_CAN                      = ID_PASSWORD_TYPE + b"\x02"
ID_PIN                      = ID_PASSWORD_TYPE + b"\x03"
ID_PUK                      = ID_PASSWORD_TYPE + b"\x04"

ID_ROLES                    = BSI_DE + b"\x03\x01\x02"
ID_IS                       = ID_ROLES + b"\x01"
ID_AT                       = ID_ROLES + b"\x02"
ID_SPECIAL_FUNCTIONS        = ID_AT + b"\x02"
ID_ST                       = ID_ROLES + b"\x03"

ID_EXTENSIONS               = BSI_DE + b"\x03\x01\x03"
ID_DESCRIPTION              = ID_EXTENSIONS + b"\x01"
ID_PLAINFORMAT              = ID_DESCRIPTION + b"\x01"
ID_HTMLFORMAT               = ID_DESCRIPTION + b"\x02"
ID_PDFFORMAT                = ID_DESCRIPTION + b"\x03"
ID_SECTOR                   = ID_EXTENSIONS + b"\x02"
ID_PS_SECTOR                = ID_EXTENSIONS + b"\x03"
ID_PICOKEY                  = ID_EXTENSIONS + b"\x0A"
ID_PICOKEY_SERIAL           = ID_PICOKEY + b"\x01"

ID_AUXILIARY_TYPE           = BSI_DE + b"\x03\x01\x04"
ID_DATEOFBIRTH              = ID_AUXILIARY_TYPE + b"\x01"
ID_DATEOFEXPIRY             = ID_AUXILIARY_TYPE + b"\x02"
ID_MUNICIPALITYID           = ID_AUXILIARY_TYPE + b"\x03"
ID_PSM_MESSAGE              = ID_AUXILIARY_TYPE + b"\x04"
ID_DGCONTENT                = ID_AUXILIARY_TYPE + b"\x05"
ID_DGCONTENT_DG1            = ID_DGCONTENT + b"\x01"
ID_DGCONTENT_DG2            = ID_DGCONTENT + b"\x02"
ID_DGCONTENT_DG3            = ID_DGCONTENT + b"\x03"
ID_DGCONTENT_DG4            = ID_DGCONTENT + b"\x04"
ID_DGCONTENT_DG5            = ID_DGCONTENT + b"\x05"
ID_DGCONTENT_DG6            = ID_DGCONTENT + b"\x06"
ID_DGCONTENT_DG7            = ID_DGCONTENT + b"\x07"
ID_DGCONTENT_DG8            = ID_DGCONTENT + b"\x08"
ID_DGCONTENT_DG9            = ID_DGCONTENT + b"\x09"
ID_DGCONTENT_DG10           = ID_DGCONTENT + b"\x0A"
ID_DGCONTENT_DG11           = ID_DGCONTENT + b"\x0B"
ID_DGCONTENT_DG12           = ID_DGCONTENT + b"\x0C"
ID_DGCONTENT_DG13           = ID_DGCONTENT + b"\x0D"
ID_DGCONTENT_DG14           = ID_DGCONTENT + b"\x0E"
ID_DGCONTENT_DG15           = ID_DGCONTENT + b"\x0F"
ID_DGCONTENT_DG16           = ID_DGCONTENT + b"\x10"
ID_DGCONTENT_DG17           = ID_DGCONTENT + b"\x11"
ID_DGCONTENT_DG18           = ID_DGCONTENT + b"\x12"
ID_DGCONTENT_DG19           = ID_DGCONTENT + b"\x13"
ID_DGCONTENT_DG20           = ID_DGCONTENT + b"\x14"
ID_DGCONTENT_DG21           = ID_DGCONTENT + b"\x15"
ID_DGCONTENT_DG22           = ID_DGCONTENT + b"\x16"

ID_SECURITY_OBJECT          = BSI_DE + b"\x03\x02\x01"

schemes = [
    ('ECDSA_SHA_1', ID_TA_ECDSA_SHA_1),
    ('ECDSA_SHA_224', ID_TA_ECDSA_SHA_224),
    ('ECDSA_SHA_256', ID_TA_ECDSA_SHA_256),
    ('ECDSA_SHA_384', ID_TA_ECDSA_SHA_384),
    ('ECDSA_SHA_512', ID_TA_ECDSA_SHA_512),
    ('RSA_v1_5_SHA_1', ID_TA_RSA_V1_5_SHA_1),
    ('RSA_v1_5_SHA_256', ID_TA_RSA_V1_5_SHA_256),
    ('RSA_v1_5_SHA_512', ID_TA_RSA_V1_5_SHA_512),
    ('RSA_PSS_SHA_1', ID_TA_RSA_PSS_SHA_1),
    ('RSA_PSS_SHA_256', ID_TA_RSA_PSS_SHA_256),
    ('RSA_PSS_SHA_512', ID_TA_RSA_PSS_SHA_512),
    ('EdDSA', ID_RI_ECDH_SHA_256)
    ]

def scheme2oid(scheme):
    for s,o in schemes:
        if (s == scheme):
            return o
    return None

def oid2scheme(oid):
    for s,o in schemes:
        if (o == oid):
            return s
    return None
