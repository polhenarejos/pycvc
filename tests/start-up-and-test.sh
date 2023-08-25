#!/bin/bash -eu

pip3 install -e .

chmod a+x tests/*.sh

## ECC
curves=("prime256v1" "prime192v1" "secp224r1" "secp256k1"  "secp384r1"  "secp521r1"  "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1")
schemes=("ECDSA_SHA_1" "ECDSA_SHA_224" "ECDSA_SHA_256" "ECDSA_SHA_384" "ECDSA_SHA_512")
for curve in ${curves[*]}; do
  for scheme in ${schemes[*]}; do
    echo -n "Create CA EC ${curve} ${scheme}... "
    ./tests/ca-create-ec.sh $curve $scheme > /dev/null
    ./tests/ca-print.sh > /dev/null
    echo -e "\tok"
  done
done

## RSA
schemes=("RSA_v1_5_SHA_1" "RSA_v1_5_SHA_256" "RSA_v1_5_SHA_512" "RSA_PSS_SHA_1" "RSA_PSS_SHA_256" "RSA_PSS_SHA_512")
for scheme in ${schemes[*]}; do
  echo -n "Create CA RSA ${scheme}... "
  ./tests/ca-create-rsa.sh $scheme > /dev/null
  ./tests/ca-print.sh > /dev/null
  echo -e "\tok"
done
