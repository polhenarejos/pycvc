# pycvc
Card Verifiable Certificates (CVC) tools for Python

## Introduction

Card Verifiable Certificates are an specification of storing electronic certificates, signed by RSA or Elliptic Curves algorithms.

In contrast to X509 certificates, CVC are more compact and are widely used by HSM cards or personal USB tokens.

pycvc implements the specifications of BSI TR 03110 to create CV certificates and requests.

pycvc can be used to make a CV request and deploy a PKI based on CVC.

## Install

```
pip install pycvc
```

## Usage

pycvc can be used by importing the package or calling the command line tools `cvc-create`, for CVC generation, and `cvc-print`, for displaying CVC information and verification.

For more information, execute `cvc-create` or `cvc-print` with `--help` flag.

Here some examples.

### Create a PKI

`cvc-create` is the tool to create certificates or requests. Call `cvc-create --help` for a complete list of parameters.

1- Setup the CA:
```bash
openssl ecparam -out ZZATCVCA00001.pem -name prime256v1 -genkey
openssl pkcs8 -topk8 -nocrypt -in ZZATCVCA00001.pem -outform DER -out ZZATCVCA00001.pkcs8
cvc-create --role=cvca --type=at --chr=ZZATCVCA00001 --valid=365 --sign-key=ZZATCVCA00001.pkcs8 --scheme=ECDSA_SHA_256
```

2- Setup the DV:
```bash
openssl ecparam -out ZZATDVCA00001.pem -name prime256v1 -genkey
openssl pkcs8 -topk8 -nocrypt -in ZZATDVCA00001.pem -outform DER -out ZZATDVCA00001.pkcs8
openssl ec -in ZZATDVCA00001.pem -out ZZATDVCA00001.pub -pubout -outform DER
cvc-create --role=dv_domestic --type=at --chr=ZZATDVCA00001 --valid=180 --sign-key=ZZATCVCA00001.pkcs8 --scheme=ECDSA_SHA_256 --sign-as=ZZATCVCA00001.cvcert --public-key=ZZATDVCA00001.pub
```

3- Create a certificate request
```bash
openssl ecparam -out ZZATTERM00001.pem -name prime256v1 -genkey
openssl pkcs8 -topk8 -nocrypt -in ZZATTERM00001.pem -outform DER -out ZZATTERM00001.pkcs8
cvc-create --chr=ZZATTERM00001 --scheme=ECDSA_SHA_256 --sign-key=ZZATTERM00001.pkcs8 --out-cert=ZZATTERM00001.cvreq --req-car=ZZATDVCA00001
```

4- Sign a certificate request
```bash
cvc-create --role=terminal --type=at --valid=60 --sign-key=ZZATDVCA00001.pkcs8 --sign-as=ZZATDVCA00001.cvcert --request=ZZATTERM00001.cvreq
```

### Validate certificates and requests

`cvc-print` is the tool for certificate validation and verification. Call `cvc-print --help` for a complete list of parameters.

The validation is performed by veryfing all signatures in the certificate chain.

1- Setup trust directory
```bash
mkdir certs
cp ZZATCVCA00001.cvcert certs/ZZATCVCA00001
cp ZZATDVCA00001.cvcert certs/ZZATDVCA00001
```

2- Validate certificates
```bash
$ cvc-print -d certs ZZATCVCA00001.cvcert
Certificate:
  Profile Identifier: 00
  CAR: ZZATCVCA00001
  Public Key:
    Scheme: ECDSA_SHA_256
    Public Point: 040e5e4d5f20ee36ac920132f7f448da353d826156e9cfd3075f9d877f9c172111a689953b9accd5011248be50ccf47480ab703b42382a7a45484fccdc738a82e7
  CHR: ZZATCVCA00001
  CHAT:
    Role:  TypeAT
    Bytes: c000000000
  Since:   2022-08-23
  Expires: 2023-08-23
Inner signature is VALID
Certificate VALID

$ cvc-print -d certs ZZATDVCA00001.cvcert
Certificate:
  Profile Identifier: 00
  CAR: ZZATCVCA00001
  Public Key:
    Scheme: ECDSA_SHA_256
    Public Point: 04b37a6588e55e9db3ea72837f4b4347028a51b1c5964ee54878bf2f856ee4abe06f1465e917c8d9ecf7170dbd61c2bc1fc37a1fa36698a33669daa6fa4c1e7400
  CHR: ZZATDVCA00001
  CHAT:
    Role:  TypeAT
    Bytes: 8000000000
  Since:   2022-08-23
  Expires: 2023-02-19
Inner signature is VALID
Certificate VALID

$ cvc-print -d certs ZZATTERM00001.cvreq
Certificate:
  Profile Identifier: 00
  CAR: ZZATTERM00001
  Public Key:
    Scheme: ECDSA_SHA_256
    Public Point: 0406358861bc93173b3931a07595eba2bbcc88b852ed0a7139067047ab8abdba9b28eb07344f4f4e8f375bdc886c86d32060e92541b4d73178f9c9c53d3d98a765
  CHR: ZZATTERM00001
Inner signature is VALID
Certificate VALID

$ cvc-print -d certs ZZATTERM00001.cvcert
Certificate:
  Profile Identifier: 00
  CAR: ZZATDVCA00001
  Public Key:
    Scheme: ECDSA_SHA_256
    Public Point: 0406358861bc93173b3931a07595eba2bbcc88b852ed0a7139067047ab8abdba9b28eb07344f4f4e8f375bdc886c86d32060e92541b4d73178f9c9c53d3d98a765
  CHR: ZZATTERM00001
  CHAT:
    Role:  TypeAT
    Bytes: 00
  Since:   2022-08-23
  Expires: 2022-10-22
Inner signature is VALID
Certificate VALID
```
