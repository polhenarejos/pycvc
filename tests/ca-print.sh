#/bin/bash -eu

mkdir -p certs
cp ZZATCVCA00001.cvcert certs/ZZATCVCA00001
cp ZZATDVCA00001.cvcert certs/ZZATDVCA00001

cvc-print --print-bits -d certs ZZATCVCA00001.cvcert
cvc-print --print-bits -d certs ZZATDVCA00001.cvcert
cvc-print --print-bits -d certs ZZATTERM00001.cvreq
cvc-print --print-bits -d certs ZZATTERM00001.cvcert
