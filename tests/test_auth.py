"""
Unit Tests for SOC Private Authentication Module (core/auth.py).
Tests login verification via Gmail, Mobile number, password hashing, and credentials update.
"""

import os
import sys
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.auth import (
    authenticate_user,
    load_credentials,
    save_credentials,
    hash_password,
    verify_password,
    update_credentials,
    reset_password,
    normalize_phone,
    normalize_email,
    phone_matches,
    reset_failed_attempts,
    get_masked_profile,
    get_default_credentials,
    CREDENTIALS_FILE
)


class TestAuthModule(unittest.TestCase):
    def setUp(self):
        # Reset to assigned owner credentials
        save_credentials(get_default_credentials())
        reset_failed_attempts("test_client")

    def tearDown(self):
        # Restore default assigned credentials
        save_credentials(get_default_credentials())

    def test_normalize_email_and_phone(self):
        self.assertEqual(normalize_email("  HemanthHemu6557@GMAIL.COM  "), "hemanthhemu6557@gmail.com")
        self.assertEqual(normalize_phone("+91-98869-66865"), "+919886966865")
        self.assertEqual(normalize_phone("(+91) 98869 66865"), "+919886966865")

    def test_phone_matching(self):
        reg = "+919886966865"
        self.assertTrue(phone_matches("+919886966865", reg))
        self.assertTrue(phone_matches("9886966865", reg))
        self.assertTrue(phone_matches("+91 98869 66865", reg))
        self.assertTrue(phone_matches("09886966865", reg))
        self.assertFalse(phone_matches("9123456789", reg))

    def test_login_with_assigned_gmail(self):
        success, msg, user = authenticate_user("hemanthhemu6557@gmail.com", "Hemanth@6557", client_id="test_client")
        self.assertTrue(success, f"Failed with: {msg}")
        self.assertIsNotNone(user)
        self.assertEqual(user["name"], "Hemanth Gowda T")
        self.assertEqual(user["auth_method"], "Gmail")

    def test_login_with_assigned_mobile_full_format(self):
        success, msg, user = authenticate_user("+919886966865", "Hemanth@6557", client_id="test_client")
        self.assertTrue(success, f"Failed with: {msg}")
        self.assertIsNotNone(user)
        self.assertEqual(user["auth_method"], "Mobile Number")

    def test_login_with_assigned_mobile_10_digits(self):
        success, msg, user = authenticate_user("9886966865", "Hemanth@6557", client_id="test_client")
        self.assertTrue(success, f"Failed with: {msg}")
        self.assertIsNotNone(user)
        self.assertEqual(user["auth_method"], "Mobile Number")

    def test_login_with_invalid_password(self):
        success, msg, user = authenticate_user("hemanthhemu6557@gmail.com", "WrongPassword!", client_id="test_client")
        self.assertFalse(success)
        self.assertIn("Invalid password", msg)
        self.assertIsNone(user)

    def test_login_with_unregistered_identifier(self):
        success, msg, user = authenticate_user("stranger@unknown.com", "Hemanth@6557", client_id="test_client")
        self.assertFalse(success)
        self.assertIn("not authorized", msg)
        self.assertIsNone(user)

    def test_update_credentials(self):
        # Update password and mobile
        ok, msg = update_credentials(
            current_password="Hemanth@6557",
            new_mobile="+919999988888",
            new_password="NewSecurePassword#2026"
        )
        self.assertTrue(ok, f"Update failed: {msg}")

        # Old password should now fail
        success_old, _, _ = authenticate_user("hemanthhemu6557@gmail.com", "Hemanth@6557", client_id="test_client")
        self.assertFalse(success_old)

        # New password with email should succeed
        success_new, _, user = authenticate_user("hemanthhemu6557@gmail.com", "NewSecurePassword#2026", client_id="test_client")
        self.assertTrue(success_new)

        # New mobile number should succeed
        success_mob, _, user = authenticate_user("9999988888", "NewSecurePassword#2026", client_id="test_client")
        self.assertTrue(success_mob)

    def test_get_masked_profile(self):
        profile = get_masked_profile()
        self.assertEqual(profile["name"], "Hemanth Gowda T")
        self.assertTrue("*" in profile["masked_email"])

    def test_reset_password_flow(self):
        # Reset password using registered Gmail
        ok, msg = reset_password("hemanthhemu6557@gmail.com", "ResetPass#2026")
        self.assertTrue(ok, f"Reset failed: {msg}")

        # Old password fails
        success_old, _, _ = authenticate_user("hemanthhemu6557@gmail.com", "Hemanth@6557", client_id="test_client")
        self.assertFalse(success_old)

        # New password succeeds
        success_new, _, _ = authenticate_user("hemanthhemu6557@gmail.com", "ResetPass#2026", client_id="test_client")
        self.assertTrue(success_new)

        # Reset password using registered mobile
        ok2, msg2 = reset_password("9886966865", "MobileReset#2026")
        self.assertTrue(ok2, f"Reset via mobile failed: {msg2}")
        success_mob, _, _ = authenticate_user("9886966865", "MobileReset#2026", client_id="test_client")
        self.assertTrue(success_mob)

    def test_strict_auth_type_enforcement(self):
        # 1. When auth_type='gmail', phone number input must be rejected
        succ_ph_in_gmail, msg1, _ = authenticate_user(
            "9886966865", "Hemanth@6557", client_id="test_client", auth_type="gmail"
        )
        self.assertFalse(succ_ph_in_gmail)
        self.assertIn("Mobile numbers are not permitted", msg1)

        # 2. When auth_type='gmail', valid Gmail succeeds
        succ_gmail, _, user1 = authenticate_user(
            "hemanthhemu6557@gmail.com", "Hemanth@6557", client_id="test_client", auth_type="gmail"
        )
        self.assertTrue(succ_gmail)
        self.assertEqual(user1["auth_method"], "Gmail")

        # 3. When auth_type='phone', Gmail input must be rejected
        succ_gm_in_phone, msg2, _ = authenticate_user(
            "hemanthhemu6557@gmail.com", "Hemanth@6557", client_id="test_client", auth_type="phone"
        )
        self.assertFalse(succ_gm_in_phone)
        self.assertIn("Gmail addresses are not permitted", msg2)

        # 4. When auth_type='phone', valid phone succeeds
        succ_phone, _, user2 = authenticate_user(
            "9886966865", "Hemanth@6557", client_id="test_client", auth_type="phone"
        )
        self.assertTrue(succ_phone)
        self.assertEqual(user2["auth_method"], "Mobile Number")


if __name__ == "__main__":
    unittest.main()
