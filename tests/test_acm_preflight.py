import importlib.util
import struct
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "src" / "t2-acm-preflight.py"
SPEC = importlib.util.spec_from_file_location("t2_acm_preflight", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ACMPreflightTests(unittest.TestCase):
    def test_ioctl_number_matches_linux_uapi_layout(self):
        self.assertEqual(MODULE.INFO_SIZE, 16)
        self.assertEqual(MODULE.T2_ACM_IOC_GET_INFO, 0x8010AC01)

    def test_ioc_rejects_out_of_range_fields(self):
        for arguments in ((4, 1, 1, 1), (1, 256, 1, 1), (1, 1, 256, 1), (1, 1, 1, 1 << 14)):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    MODULE._ioc(*arguments)

    def test_clean_generation_metadata(self):
        self.assertEqual(
            MODULE.parse_info(struct.pack(MODULE.INFO_FORMAT, 4, 16384, 0)),
            (4, 16384),
        )

    def test_poisoned_generation_requires_reboot(self):
        with self.assertRaisesRegex(RuntimeError, "reboot required"):
            MODULE.parse_info(
                struct.pack(
                    MODULE.INFO_FORMAT,
                    5,
                    16384,
                    MODULE.T2_ACM_INFO_F_POISONED,
                )
            )


if __name__ == "__main__":
    unittest.main()
