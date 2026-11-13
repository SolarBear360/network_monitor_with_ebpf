#!/usr/bin/env python3

import ctypes
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("tcpip_pakage_expire.py")


class FakeLibc:
    def __init__(self, result, errno=0):
        self.result = result
        self.errno = errno

    def syscall(self, *_args):
        ctypes.set_errno(self.errno)
        return self.result


class BpfSyscallCounterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="expire-test-")
        original_cwd = os.getcwd()
        try:
            os.chdir(cls.temp_dir.name)
            spec = importlib.util.spec_from_file_location(
                "tcpip_pakage_expire_under_test", MODULE_PATH
            )
            cls.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.module)
        finally:
            os.chdir(original_cwd)

    @classmethod
    def tearDownClass(cls):
        for handler in cls.module.logger.handlers:
            handler.close()
        cls.temp_dir.cleanup()

    def setUp(self):
        self.module.BPF_SYSCALL_SUCCESS_COUNT = 0

    def test_successful_syscall_increments_counter(self):
        self.module.libc = FakeLibc(0)

        result = self.module.bpf_syscall(
            self.module.BPF_MAP_LOOKUP_ELEM,
            self.module.BPFAttrLookup(),
        )

        self.assertEqual(result, 0)
        self.assertEqual(self.module.BPF_SYSCALL_SUCCESS_COUNT, 1)

    def test_expected_enoent_does_not_increment_counter(self):
        self.module.libc = FakeLibc(-1, errno=2)

        result = self.module.bpf_syscall(
            self.module.BPF_MAP_GET_NEXT_KEY,
            self.module.BPFAttrGetNextKey(),
            enoent_is_none=True,
        )

        self.assertIsNone(result)
        self.assertEqual(self.module.BPF_SYSCALL_SUCCESS_COUNT, 0)


if __name__ == "__main__":
    unittest.main()
