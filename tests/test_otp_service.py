"""
Unit Tests for Real OTP Dispatch Service (core/otp_service.py).
Tests email and SMS gateway configuration and dispatch mechanics.
"""

import os
import sys
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.otp_service import (
    get_smtp_config,
    get_sms_config,
    send_email_otp,
    send_sms_otp,
    dispatch_real_otp,
    save_gateway_config
)


class TestOTPService(unittest.TestCase):
    def test_smtp_and_sms_config_loading(self):
        smtp_cfg = get_smtp_config()
        self.assertIn("server", smtp_cfg)
        self.assertEqual(smtp_cfg["server"], "smtp.gmail.com")
        self.assertEqual(smtp_cfg["port"], 587)

        sms_cfg = get_sms_config()
        self.assertIn("fast2sms_key", sms_cfg)

    def test_dispatch_real_otp_unconfigured(self):
        # Testing dispatch without credentials returns safe error messages without throwing
        res = dispatch_real_otp("test@example.com", "999888", "test@example.com", "9886966865")
        self.assertIsInstance(res, dict)
        self.assertIn("email_sent", res)
        self.assertIn("sms_sent", res)
        self.assertIn("any_sent", res)


if __name__ == "__main__":
    unittest.main()
