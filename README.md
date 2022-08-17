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
