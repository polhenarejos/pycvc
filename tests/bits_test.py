import sys
import unittest
import binascii
import logging

from cvc.certificates import CVC


DUMMY_CERT = "7f2181e37f4e819c5f290100420d5a5a41544456434130303030317f494f060a04007f00070202020203864104ed9e6911b2b4c39c7571f717ca0b61b7074fb05701d90f4474ee7e314d42828eb54ec3278a4cfc14cfe83014f01b534733e42ecee9a347c9c85691226a4692665f200d5a5a41545445524d30303030317f4c12060904007f000703010202530500200000045f25060203000900085f24060203010100075f37406e7f93614c8a63bbecc05ac8765055fe81b0d8a27389a8489aaed6ae9176503693d3016d1109d2cade63d4f0b661b142d7fc3368369ac3fe9c86154659a17518"

# Authorization bits according to
# BSI-TR-03110-4 Chapter 2.2.3.2 Table 4
AuthorizationBits = {
    39: "Upper Role Bit",
    38: "Lower Role Bit",
    37: "Write Datagroup 17",
    36: "Write Datagroup 18",
    35: "Write Datagroup 19",
    34: "Write Datagroup 20",
    33: "Write Datagroup 21",
    32: "Write Datagroup 22",
    31: "RFU",
    30: "PSA",
    29: "Read Datagroup 22",
    28: "Read Datagroup 21",
    27: "Read Datagroup 20",
    26: "Read Datagroup 19",
    25: "Read Datagroup 18",
    24: "Read Datagroup 17",
    23: "Read Datagroup 16",
    22: "Read Datagroup 15",
    21: "Read Datagroup 14",
    20: "Read Datagroup 13",
    19: "Read Datagroup 12",
    18: "Read Datagroup 11",
    17: "Read Datagroup 10",
    16: "Read Datagroup 09",
    15: "Read Datagroup 08",
    14: "Read Datagroup 07",
    13: "Read Datagroup 06",
    12: "Read Datagroup 05",
    11: "Read Datagroup 04",
    10: "Read Datagroup 03",
    9: "Read Datagroup 02",
    8: "Read Datagroup 01",
    7: "Install Qualified Certificate",
    6: "Install Certificate",
    5: "PIN Management",
    4: "CAN allowed",
    3: "Privileged Terminal",
    2: "Restricted Identification",
    1: "Municipality ID Verification",
    0: "Age Verification",
}


class TestAuthorizationBits(unittest.TestCase):
    log = logging.getLogger("AuthBits")

    def test_parse_authorization_bits(self):
        cvc = CVC().decode(binascii.unhexlify(DUMMY_CERT))
        self.log.info(cvc)
        bits = cvc.decode_authorization_bits()
        self.log.info("BITS:" + bits + " " + str(len(bits)))
        for bit in AuthorizationBits:
            self.log.info(
                " Bit "
                + str(bit)
                + " "
                + str(bits[bit] == "1")
                + "\t\t"
                + AuthorizationBits[bit]
            )


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr)
    logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
