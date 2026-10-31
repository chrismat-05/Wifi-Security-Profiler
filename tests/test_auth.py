"""
Tests for auth module.
Verifies user registration, credential validation, case-insensitive duplicate checks,
input constraints, and secure password hashing.
"""

import unittest
import os
import json
import auth


class TestAuth(unittest.TestCase):
    """Test suite for user authentication and persistence."""

    def setUp(self):
        """Configure isolated test users file."""
        self.original_users_file = auth.USERS_FILE
        self.test_users_file = "test_users_sandbox.json"
        auth.USERS_FILE = self.test_users_file
        # Start clean
        if os.path.exists(self.test_users_file):
            os.remove(self.test_users_file)

    def tearDown(self):
        """Clean up test users file and restore original."""
        if os.path.exists(self.test_users_file):
            os.remove(self.test_users_file)
        auth.USERS_FILE = self.original_users_file

    def test_register_valid_user(self):
        """Registering a new valid user should succeed and write hashed password."""
        ok, msg = auth.register_user("sec_analyst", "SecretPass123!")
        self.assertTrue(ok)
        self.assertIn("registered successfully", msg)

        users = auth.load_users()
        self.assertIn("sec_analyst", users)
        self.assertNotEqual(users["sec_analyst"]["password_hash"], "SecretPass123!")
        self.assertEqual(len(users["sec_analyst"]["password_hash"]), 64)

    def test_register_duplicate_case_insensitive(self):
        """Duplicate usernames with different casing must be rejected."""
        ok1, _ = auth.register_user("cyber_user", "password123")
        self.assertTrue(ok1)

        ok2, msg2 = auth.register_user("CYBER_USER", "anotherpassword")
        self.assertFalse(ok2)
        self.assertIn("already exists", msg2)

    def test_register_invalid_inputs(self):
        """Empty or excessively short credentials must be rejected."""
        # Empty inputs
        ok, msg = auth.register_user("", "pass123")
        self.assertFalse(ok)
        self.assertIn("cannot be empty", msg)

        # Short username (< 3 chars)
        ok, msg = auth.register_user("ab", "pass123")
        self.assertFalse(ok)
        self.assertIn("at least 3 characters", msg)

        # Short password (< 4 chars)
        ok, msg = auth.register_user("valid_user", "123")
        self.assertFalse(ok)
        self.assertIn("at least 4 characters", msg)

    def test_validate_user_credentials(self):
        """Validating correct credentials returns True; wrong password returns False."""
        auth.register_user("tester_one", "correct_horse_battery")

        # Correct password
        valid, user_data = auth.validate_user("tester_one", "correct_horse_battery")
        self.assertTrue(valid)
        self.assertIsNotNone(user_data)
        self.assertEqual(user_data["username"], "tester_one")

        # Incorrect password
        valid, user_data = auth.validate_user("tester_one", "wrong_password")
        self.assertFalse(valid)
        self.assertIsNone(user_data)

    def test_validate_nonexistent_user(self):
        """Attempting to log in as an unregistered user returns False."""
        valid, user_data = auth.validate_user("ghost_user", "some_password")
        self.assertFalse(valid)
        self.assertIsNone(user_data)

    def test_password_hashing_consistency(self):
        """The hashing function should produce deterministic SHA-256 output."""
        h1 = auth._hash_password("MySecurePassphrase")
        h2 = auth._hash_password("MySecurePassphrase")
        h3 = auth._hash_password("DifferentPassphrase")
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)


if __name__ == "__main__":
    unittest.main()
