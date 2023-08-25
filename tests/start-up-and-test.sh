#!/bin/bash -eu

pip3 install .

## ECC
openssl ecparam -out ZZATCVCA00001.pem -name prime256v1 -genkey
openssl pkcs8 -topk8 -nocrypt -in ZZATCVCA00001.pem -outform DER -out ZZATCVCA00001.pkcs8
cvc-create --role=cvca --type=at --chr=ZZATCVCA00001 --days=365 --sign-key=ZZATCVCA00001.pkcs8 --scheme=ECDSA_SHA_256

openssl ecparam -out ZZATDVCA00001.pem -name prime256v1 -genkey
openssl pkcs8 -topk8 -nocrypt -in ZZATDVCA00001.pem -outform DER -out ZZATDVCA00001.pkcs8
openssl ec -in ZZATDVCA00001.pem -out ZZATDVCA00001.pub -pubout -outform DER
cvc-create --role=dv_domestic --type=at --chr=ZZATDVCA00001 --days=180 --sign-key=ZZATCVCA00001.pkcs8 --scheme=ECDSA_SHA_256 --sign-as=ZZATCVCA00001.cvcert --public-key=ZZATDVCA00001.pub

openssl ecparam -out ZZATTERM00001.pem -name prime256v1 -genkey
openssl pkcs8 -topk8 -nocrypt -in ZZATTERM00001.pem -outform DER -out ZZATTERM00001.pkcs8
cvc-create --chr=ZZATTERM00001 --scheme=ECDSA_SHA_256 --sign-key=ZZATTERM00001.pkcs8 --out-cert=ZZATTERM00001.cvreq --req-car=ZZATDVCA00001

cvc-create --role=terminal --type=at --days=60 --sign-key=ZZATDVCA00001.pkcs8 --sign-as=ZZATDVCA00001.cvcert --request=ZZATTERM00001.cvreq

mkdir -p certs
cp ZZATCVCA00001.cvcert certs/ZZATCVCA00001
cp ZZATDVCA00001.cvcert certs/ZZATDVCA00001

cvc-print -d certs ZZATCVCA00001.cvcert
cvc-print -d certs ZZATDVCA00001.cvcert
cvc-print -d certs ZZATTERM00001.cvreq
cvc-print -d certs ZZATTERM00001.cvcert

## RSA
openssl genrsa -out ZZATCVCA00001.pem 3072
openssl pkcs8 -topk8 -nocrypt -in ZZATCVCA00001.pem -outform DER -out ZZATCVCA00001.pkcs8
cvc-create --role=cvca --type=at --chr=ZZATCVCA00001 --days=365 --sign-key=ZZATCVCA00001.pkcs8 --scheme=RSA_v1_5_SHA_256

openssl genrsa -out ZZATDVCA00001.pem 2048
openssl pkcs8 -topk8 -nocrypt -in ZZATDVCA00001.pem -outform DER -out ZZATDVCA00001.pkcs8
openssl rsa -in ZZATDVCA00001.pem -out ZZATDVCA00001.pub -pubout -outform DER
cvc-create --role=dv_domestic --type=at --chr=ZZATDVCA00001 --days=180 --sign-key=ZZATCVCA00001.pkcs8 --scheme=RSA_v1_5_SHA_256 --sign-as=ZZATCVCA00001.cvcert --public-key=ZZATDVCA00001.pub

openssl genrsa -out ZZATTERM00001.pem 2048
openssl pkcs8 -topk8 -nocrypt -in ZZATTERM00001.pem -outform DER -out ZZATTERM00001.pkcs8
cvc-create --chr=ZZATTERM00001 --scheme=RSA_v1_5_SHA_256 --sign-key=ZZATTERM00001.pkcs8 --out-cert=ZZATTERM00001.cvreq --req-car=ZZATDVCA00001

cvc-create --role=terminal --type=at --days=60 --sign-key=ZZATDVCA00001.pkcs8 --sign-as=ZZATDVCA00001.cvcert --request=ZZATTERM00001.cvreq

mkdir -p certs
cp ZZATCVCA00001.cvcert certs/ZZATCVCA00001
cp ZZATDVCA00001.cvcert certs/ZZATDVCA00001

cvc-print -d certs ZZATCVCA00001.cvcert
cvc-print -d certs ZZATDVCA00001.cvcert
cvc-print -d certs ZZATTERM00001.cvreq
cvc-print -d certs ZZATTERM00001.cvcert
