import binascii
import argparse


def file_to_hex(filename):
    with open(filename, "rb") as f:
        content = f.read()
        print(binascii.hexlify(content))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Helper util to convert CVCert(or any file) to hex string"
    )
    parser.add_argument("file", help="File to convert to hex")

    args = parser.parse_args()

    file_to_hex(args.file)
