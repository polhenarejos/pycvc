#/bin/bash -eu

check_cert() {
    e=$(cvc-print -d certs $1)
    grep -q "is VALID" <<< $e || (echo -e "${FAIL}" && exit 1)
    grep -q "Certificate VALID" <<< $e || (echo -e "${FAIL}" && exit 1)
}

mkdir -p certs
cp ZZATCVCA00001.cvcert certs/ZZATCVCA00001
cp ZZATDVCA00001.cvcert certs/ZZATDVCA00001

check_cert "ZZATCVCA00001.cvcert"
check_cert "ZZATDVCA00001.cvcert"
check_cert "ZZATTERM00001.cvreq"
check_cert "ZZATTERM00001.cvcert"
