#!/bin/bash -eu

pip3 install -e .

OK="\033[32mok\033[0m"
FAIL="\033[31mfail\033[0m"

chmod a+x tests/*.sh

echo "=== Test CA creation ==="
## ECC
curves=("prime256v1" "prime192v1" "secp224r1" "secp256k1"  "secp384r1"  "secp521r1"  "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1")
schemes=("ECDSA_SHA_1" "ECDSA_SHA_224" "ECDSA_SHA_256" "ECDSA_SHA_384" "ECDSA_SHA_512")
for curve in ${curves[*]}; do
  for scheme in ${schemes[*]}; do
    echo -n "Create CA EC ${curve} ${scheme}... "
    ./tests/ca-create-ec.sh $curve $scheme > /dev/null || echo -e "\t${FAIL}"
    ./tests/ca-print.sh > /dev/null || echo -e "\t${FAIL}"
    echo -e "\t${OK}"
  done
done

## RSA
schemes=("RSA_v1_5_SHA_1" "RSA_v1_5_SHA_256" "RSA_v1_5_SHA_512" "RSA_PSS_SHA_1" "RSA_PSS_SHA_256" "RSA_PSS_SHA_512")
for scheme in ${schemes[*]}; do
  echo -n "Create CA RSA ${scheme}... "
  ./tests/ca-create-rsa.sh $scheme > /dev/null
  ./tests/ca-print.sh > /dev/null
  echo -e "\t${OK}"
done

## EdDSA
schemes=("Ed25519" "Ed448")
for scheme in ${schemes[*]}; do
  echo -n "Create CA EdDSA ${scheme}... "
  ./tests/ca-create-ed.sh $scheme > /dev/null
  ./tests/ca-print.sh
  echo -e "\t${OK}"
done

./tests/ca-create-ec.sh prime256v1 ECDSA_SHA_256 > /dev/null

test_arg() {
  args=$2
  nargs=${#args[@]}
  npad=$((((nargs+8-1)/8)*2))
  for ix in ${!args[@]}; do
    arg=${args[$ix]}
    bytes=$((1<<(nargs-ix-1)))
    echo -n "Flag ${arg}... "
    cvc-create --role=terminal --type=$1 --days=60 --sign-key=ZZATDVCA00001.pkcs8 --sign-as=ZZATDVCA00001.cvcert --request=ZZATTERM00001.cvreq --${arg}
    e=$(cvc-print -d certs ZZATTERM00001.cvcert)
    argr=${arg//-/_}
    chat=$(printf "%0${npad}X" ${bytes})
    grep -q "${argr}" <<< $e || (echo -e "${FAIL}" && exit 1)
    grep -q "is VALID" <<< $e || (echo -e "${FAIL}" && exit 1)
    grep -q "Certificate VALID" <<< $e || (echo -e "${FAIL}" && exit 1)
    grep -q "Bytes: ${chat}" <<< $e && echo -e "\t${OK}" || (echo -e "\t${FAIL}" && exit 1)
  done
}

echo "=== Test AT fields ==="
args=('write-dg17' 'write-dg18' 'write-dg19' 'write-dg20' 'write-dg21' 'write-dg22' 'rfu31' 'psa' 'read-dg22' 'read-dg21' 'read-dg20' 'read-dg19' 'read-dg18' 'read-dg17' 'read-dg16' 'read-dg15' 'read-dg14' 'read-dg13' 'read-dg12' 'read-dg11' 'read-dg10' 'read-dg9' 'read-dg8' 'read-dg7' 'read-dg6' 'read-dg5' 'read-dg4' 'read-dg3' 'read-dg2' 'read-dg1' 'install-qual-cert' 'install-cert' 'pin-management' 'can-allowed' 'privileged' 'rid' 'verify-community' 'verify-age')
test_arg "at" $args

echo "=== Test IS fields ==="
args=('rfu5' 'rfu4' 'rfu3' 'rfu2' 'read-iris' 'read-fingerprint')
test_arg "is" $args

echo "=== Test ST fields ==="
args=('rfu5' 'rfu4' 'rfu3' 'rfu2' 'gen-qual-sig' 'gen-sig')
test_arg "st" $args
