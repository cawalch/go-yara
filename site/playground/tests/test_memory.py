import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('builder', Path(__file__).resolve().parents[1] / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class MemoryCapTests(unittest.TestCase):
    def test_changes_only_memory_limits(self):
        original = b'\0asm\x01\0\0\0' + b'\0\x02\x01x' + b'\x05\x03\x01\x00\x60'
        capped = builder.cap_memory(original, 128 * 1024 * 1024)
        self.assertEqual(capped, original[:12] + b'\x05\x05\x01\x01\x60\x80\x10')

    def test_rejects_missing_or_unfamiliar_memory(self):
        for data in [b'\0asm\x01\0\0\0', b'\0asm\x01\0\0\0\x05\x04\x01\x02\x60\x00']:
            with self.assertRaises(ValueError):
                builder.cap_memory(data, 128 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
