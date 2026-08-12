import unittest

from lib.util import force_int, keys_exist


class TestForceInt(unittest.TestCase):

    def test_int_is_returned_unchanged(self):
        value = 42

        result = force_int(value)

        self.assertEqual(result, 42)
        self.assertIs(result, value)

    def test_decimal_string(self):
        self.assertEqual(force_int("42"), 42)

    def test_hexadecimal_string(self):
        self.assertEqual(force_int("0x2a"), 42)

    def test_hexadecimal_string_uppercase_digits(self):
        self.assertEqual(force_int("0xFF"), 255)

    def test_string_with_trailing_content(self):
        self.assertEqual(force_int("42 something"), 42)

    def test_hex_string_with_trailing_content(self):
        self.assertEqual(force_int("0x2a something"), 42)

    def test_non_int_non_string_is_returned_unchanged(self):
        value = 3.14

        result = force_int(value)

        self.assertEqual(result, value)
        self.assertIs(result, value)


class TestKeysExist(unittest.TestCase):

    def test_empty_path_returns_true(self):
        self.assertTrue(keys_exist({}, []))
        self.assertTrue(keys_exist({"a": 1}, []))

    def test_single_existing_key(self):
        self.assertTrue(keys_exist({"a": 1}, ["a"]))

    def test_single_missing_key(self):
        self.assertFalse(keys_exist({"a": 1}, ["b"]))

    def test_nested_existing_keys(self):
        data = {
            "a": {
                "b": {
                    "c": 42
                }
            }
        }

        self.assertTrue(keys_exist(data, ["a", "b", "c"]))

    def test_nested_missing_key(self):
        data = {
            "a": {
                "b": {
                    "c": 42
                }
            }
        }

        self.assertFalse(keys_exist(data, ["a", "b", "missing"]))


if __name__ == "__main__":
    unittest.main()