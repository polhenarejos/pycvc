import sys
import unittest
import binascii
import logging

from cvc.certificates import CVC
from cvc.tools.cvc_print import AuthorizationBits, decode_authorization_bits

# created with --rid --read-dg1 --write-dg22 --verify-age --install-cert
CERT_WITH_RID_READ_DG1_WRITE_DG22_VERIFY_AGE_INSTALL_CERT = b"7f2181e37f4e819c5f290100420d5a5a41544456434130303030317f494f060a04007f000702020202038641043eb3b230afe41d99b0e564b8673ca9f830de0c4f1a21ccfbebbb378b980d2384750751df9403878cb46f9297d5507a759e80ab463b0bb233e5dce068ddeb55665f200d5a5a41545445524d30303030317f4c12060904007f000703010202530501000001455f25060203000900095f24060203010100085f374094d5eb4162b8f38ab531b2259af0a8aaa7fdadaa126d21948e5d68a739bac4141b59ca43fb411165b7725c39ad4fa71ab548ede169616282de72860e7de9179b"
# created with --rid --read-dg22
CERT_WITH_RID_READ_DG22 = b"7f2181e37f4e819c5f290100420d5a5a41544456434130303030317f494f060a04007f00070202020203864104ed9e6911b2b4c39c7571f717ca0b61b7074fb05701d90f4474ee7e314d42828eb54ec3278a4cfc14cfe83014f01b534733e42ecee9a347c9c85691226a4692665f200d5a5a41545445524d30303030317f4c12060904007f000703010202530500200000045f25060203000900085f24060203010100075f37406e7f93614c8a63bbecc05ac8765055fe81b0d8a27389a8489aaed6ae9176503693d3016d1109d2cade63d4f0b661b142d7fc3368369ac3fe9c86154659a17518"

class TestAuthorizationBits(unittest.TestCase):
    log = logging.getLogger("AuthBits")

    def test_parse_authorization_bits(self):
        self.log.info(
            " Testing CERT_WITH_RID_READ_DG1_WRITE_DG22_VERIFY_AGE_INSTALL_CERT"
        )
        cvc = CVC().decode(
            binascii.unhexlify(
                CERT_WITH_RID_READ_DG1_WRITE_DG22_VERIFY_AGE_INSTALL_CERT
            )
        )
        self.log.info(cvc)
        bits = decode_authorization_bits(cvc.role().find(0x53).data())

        self.log.info("Raw authorization bits:" + bits)
        for bit in AuthorizationBits:
            self.log.info(
                "Field '{:<32}' has value: {:^6} at offset: {:2}".format(
                    bit,
                    str(bits[AuthorizationBits[bit]] == "1"),
                    AuthorizationBits[bit],
                )
            )
        self.assertTrue(bits[AuthorizationBits["Age Verification"]])
        self.assertTrue(bits[AuthorizationBits["Restricted Identification"]])
        self.assertTrue(bits[AuthorizationBits["Install Certificate"]])
        self.assertTrue(bits[AuthorizationBits["Read Datagroup 01"]])
        self.assertTrue(bits[AuthorizationBits["Write Datagroup 22"]])

        self.log.info(" Testing CERT_WITH_RID_READ_DG22")
        cvc = CVC().decode(binascii.unhexlify(CERT_WITH_RID_READ_DG22))
        self.log.info(cvc)
        bits = decode_authorization_bits(cvc.role().find(0x53).data())

        self.log.info("Raw authorization bits:" + bits)
        for bit in AuthorizationBits:
            self.log.info(
                "Field '{:<32}' has value: {:^6} at offset: {:2}".format(
                    bit,
                    str(bits[AuthorizationBits[bit]] == "1"),
                    AuthorizationBits[bit],
                )
            )
        self.assertTrue(bits[AuthorizationBits["Restricted Identification"]])
        self.assertTrue(bits[AuthorizationBits["Read Datagroup 22"]])


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr)
    logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
