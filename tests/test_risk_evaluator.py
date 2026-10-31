"""
Tests for risk_evaluator module.
Verifies vulnerability pattern detection, quantitative scoring,
risk categorization, recommendation generation, and batch aggregation.
"""

import unittest
from risk_evaluator import (
    identify_vulnerability_patterns,
    classify_risk_level,
    generate_recommendations,
    evaluate_wifi_risk,
    batch_process_profiles
)


class TestRiskEvaluator(unittest.TestCase):
    """Test suite for Wi-Fi risk evaluation engine."""

    def test_open_unencrypted_network_triggers_critical_risk(self):
        """Open / Unencrypted networks must trigger OPEN_NETWORK pattern and CRITICAL risk."""
        profile = {
            "ssid": "Public_Coffee_Free",
            "security": "Open",
            "encryption": "None",
            "wps": "Disabled",
            "password_strength": "Weak",
            "captive_portal": "None"
        }
        res = evaluate_wifi_risk(profile)
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertGreaterEqual(res["score"], 65)
        pattern_ids = [p["id"] for p in res["patterns"]]
        self.assertIn("OPEN_NETWORK", pattern_ids)
        self.assertTrue(any("WPA2" in rec or "WPA3" in rec for rec in res["recommendations"]))

    def test_wep_deprecated_triggers_critical(self):
        """Obsolete WEP networks must trigger WEP_DEPRECATED pattern and CRITICAL risk."""
        profile = {
            "ssid": "LegacyRouter",
            "security": "WEP",
            "encryption": "None",
            "wps": "Disabled",
            "password_strength": "Weak",
            "captive_portal": "None"
        }
        res = evaluate_wifi_risk(profile)
        self.assertEqual(res["risk_level"], "CRITICAL")
        pattern_ids = [p["id"] for p in res["patterns"]]
        self.assertIn("WEP_DEPRECATED", pattern_ids)

    def test_wpa3_aes_strong_password_triggers_low_risk(self):
        """WPA3 with AES encryption and strong password must achieve LOW risk and high security."""
        profile = {
            "ssid": "SecureCorp_Office",
            "security": "WPA3",
            "encryption": "AES",
            "wps": "Disabled",
            "password_strength": "Strong",
            "captive_portal": "None"
        }
        res = evaluate_wifi_risk(profile)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["score"], 0)
        self.assertEqual(len(res["patterns"]), 0)
        self.assertTrue(any("best practices" in rec.lower() for rec in res["recommendations"]))

    def test_tkip_and_wps_vulnerabilities(self):
        """TKIP cipher and WPS enabled should both register high-severity vulnerabilities."""
        profile = {
            "ssid": "HomeNetworkOld",
            "security": "WPA",
            "encryption": "TKIP",
            "wps": "Enabled",
            "password_strength": "Medium",
            "captive_portal": "None"
        }
        res = evaluate_wifi_risk(profile)
        pattern_ids = [p["id"] for p in res["patterns"]]
        self.assertIn("TKIP_LEGACY", pattern_ids)
        self.assertIn("WPS_ENABLED", pattern_ids)
        self.assertIn("MEDIUM_PASSWORD", pattern_ids)
        self.assertIn(res["risk_level"], ["HIGH", "CRITICAL"])

    def test_captive_portal_pattern_and_recommendation(self):
        """Captive portal detection must add risk penalty and advise VPN / HTTPS verification."""
        profile = {
            "ssid": "Campus_Guest",
            "security": "WPA2",
            "encryption": "AES",
            "wps": "Disabled",
            "password_strength": "Strong",
            "captive_portal": "Detected"
        }
        res = evaluate_wifi_risk(profile)
        pattern_ids = [p["id"] for p in res["patterns"]]
        self.assertIn("CAPTIVE_PORTAL", pattern_ids)
        self.assertEqual(res["score"], 30)  # WPA2(15) + CaptivePortal(15) = 30
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertTrue(any("VPN" in rec for rec in res["recommendations"]))

    def test_password_strength_scoring(self):
        """Password strength should incrementally adjust risk score penalties."""
        base = {
            "ssid": "TestNet",
            "security": "WPA2",
            "encryption": "AES",
            "wps": "Disabled",
            "captive_portal": "None"
        }

        eval_strong = evaluate_wifi_risk({**base, "password_strength": "Strong"})
        eval_medium = evaluate_wifi_risk({**base, "password_strength": "Medium"})
        eval_weak = evaluate_wifi_risk({**base, "password_strength": "Weak"})

        self.assertEqual(eval_strong["score"], 15)  # WPA2 base
        self.assertEqual(eval_medium["score"], 25)  # 15 + 10
        self.assertEqual(eval_weak["score"], 35)    # 15 + 20
        self.assertLess(eval_strong["score"], eval_medium["score"])
        self.assertLess(eval_medium["score"], eval_weak["score"])

    def test_batch_process_profiles_aggregation(self):
        """Batch processing must aggregate total counts and classify risk levels properly."""
        sample_profiles = [
            {"ssid": "Net1", "security": "Open", "encryption": "None", "wps": "Disabled", "password_strength": "Weak", "captive_portal": "None"},
            {"ssid": "Net2", "security": "WPA3", "encryption": "AES", "wps": "Disabled", "password_strength": "Strong", "captive_portal": "None"},
            {"ssid": "Net3", "security": "WPA2", "encryption": "AES", "wps": "Enabled", "password_strength": "Weak", "captive_portal": "None"}
        ]
        summary = batch_process_profiles(sample_profiles)
        self.assertEqual(summary["total_profiles"], 3)
        self.assertIn("CRITICAL", summary["risk_counts"])
        self.assertIn("LOW", summary["risk_counts"])
        self.assertEqual(len(summary["evaluated_profiles"]), 3)

    def test_edge_case_empty_and_unknown_fields(self):
        """Evaluating profile with missing/empty fields should safely fall back without errors."""
        res = evaluate_wifi_risk({})
        self.assertIn("risk_level", res)
        self.assertIn("score", res)
        self.assertIsInstance(res["patterns"], list)
        self.assertIsInstance(res["recommendations"], list)


if __name__ == "__main__":
    unittest.main()
