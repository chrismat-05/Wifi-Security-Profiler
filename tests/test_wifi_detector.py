"""
Tests for wifi_detector module.
Verifies netsh authentication/cipher mapping, captive portal detection heuristics,
and hardware detection safety fallbacks.
"""

import unittest
from wifi_detector import (
    parse_netsh_auth_and_cipher,
    check_captive_portal,
    detect_connected_wifi,
    scan_nearby_networks
)


class TestWifiDetector(unittest.TestCase):
    """Test suite for Wi-Fi interface probing and telemetry parsing."""

    def test_parse_netsh_open(self):
        """Open authentication string should map to Open security and None cipher."""
        sec, enc, pw, wps = parse_netsh_auth_and_cipher("Open", "None")
        self.assertEqual(sec, "Open")
        self.assertEqual(enc, "None")
        self.assertEqual(pw, "Weak")
        self.assertEqual(wps, "Disabled")

    def test_parse_netsh_wpa2_aes(self):
        """WPA2-Personal with CCMP should map to WPA2 and AES."""
        sec, enc, pw, wps = parse_netsh_auth_and_cipher("WPA2-Personal", "CCMP")
        self.assertEqual(sec, "WPA2")
        self.assertEqual(enc, "AES")
        self.assertEqual(pw, "Strong")
        self.assertEqual(wps, "Enabled")

    def test_parse_netsh_wpa3(self):
        """WPA3-Personal should map to WPA3 and Disabled WPS."""
        sec, enc, pw, wps = parse_netsh_auth_and_cipher("WPA3-Personal", "CCMP")
        self.assertEqual(sec, "WPA3")
        self.assertEqual(enc, "AES")
        self.assertEqual(wps, "Disabled")

    def test_parse_netsh_wep_tkip(self):
        """WEP authentication and TKIP encryption should map correctly."""
        sec, enc, pw, wps = parse_netsh_auth_and_cipher("WEP", "TKIP")
        self.assertEqual(sec, "WEP")
        self.assertEqual(enc, "TKIP")
        self.assertEqual(pw, "Weak")

    def test_check_captive_portal_open_heuristic(self):
        """Open networks should automatically be flagged as requiring captive portal."""
        res = check_captive_portal(security="Open", ssid="Airport_Free_Wifi")
        self.assertTrue(res["has_captive_portal"])
        self.assertEqual(res["status_label"], "Detected")
        self.assertIn("Open", res["details"])

    def test_check_captive_portal_keyword_heuristics(self):
        """SSIDs matching known public/institutional keywords should trigger captive portal detection."""
        keywords = ["STUDENT_WIFI", "KJIT-GUEST", "CITY_LIBRARY_FREE", "HOTEL_PORTAL"]
        for ssid in keywords:
            res = check_captive_portal(security="WPA2", ssid=ssid)
            self.assertTrue(res["has_captive_portal"], f"Failed to detect portal for SSID: {ssid}")
            self.assertEqual(res["status_label"], "Detected")

    def test_hardware_detection_graceful_handling(self):
        """Hardware functions should safely return structured dictionaries or lists without crashing."""
        active = detect_connected_wifi()
        self.assertIsInstance(active, dict)
        self.assertIn("connected", active)

        nearby = scan_nearby_networks()
        self.assertIsInstance(nearby, list)


if __name__ == "__main__":
    unittest.main()
