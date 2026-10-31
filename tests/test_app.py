"""
Tests for Flask Web Application (app.py).
Verifies route accessibility, authentication guards, manual profile addition,
JSON and CSV report exports, profile deletion, and API security.
"""

import unittest
import os
import json
import app
import auth


class TestWebApp(unittest.TestCase):
    """Integration test suite for Flask web application."""

    def setUp(self):
        """Set up test environment and isolate storage files."""
        self.original_profile_file = app.PROFILE_FILE
        self.original_users_file = auth.USERS_FILE

        self.test_profile_file = "test_wifi_profile_sandbox.json"
        self.test_users_file = "test_users_sandbox.json"

        app.PROFILE_FILE = self.test_profile_file
        auth.USERS_FILE = self.test_users_file

        # Prepopulate sandbox profile
        sample_profiles = [
            {
                "ssid": "TestSandboxAP",
                "security": "WPA2",
                "encryption": "AES",
                "wps": "Disabled",
                "password_strength": "Strong",
                "captive_portal": "None"
            }
        ]
        with open(self.test_profile_file, "w", encoding="utf-8") as f:
            json.dump(sample_profiles, f)

        # Register test user
        auth.register_user("web_tester", "Pass1234!")

        app.app.config["TESTING"] = True
        app.app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.app.test_client()

    def tearDown(self):
        """Clean up sandbox files and restore original paths."""
        if os.path.exists(self.test_profile_file):
            os.remove(self.test_profile_file)
        if os.path.exists(self.test_users_file):
            os.remove(self.test_users_file)

        app.PROFILE_FILE = self.original_profile_file
        auth.USERS_FILE = self.original_users_file

    def test_home_page(self):
        """Home page should render with 200 OK and brand title."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Wi-Fi Security Profiler", res.data)

    def test_dashboard_unauthenticated_redirect(self):
        """Accessing dashboard without a session should redirect to login."""
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

    def test_login_and_logout_flow(self):
        """User can log in successfully and subsequently log out."""
        # Log in
        login_res = self.client.post("/login", data={
            "username": "web_tester",
            "password": "Pass1234!"
        }, follow_redirects=True)
        self.assertEqual(login_res.status_code, 200)
        self.assertIn(b"Logged in successfully", login_res.data)

        # Log out
        logout_res = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_res.status_code, 200)
        self.assertIn(b"You have been logged out", logout_res.data)

    def test_manual_add_profile(self):
        """Logged-in user can manually audit and save a new Wi-Fi profile."""
        with self.client.session_transaction() as sess:
            sess["username"] = "web_tester"

        res = self.client.post("/manual_add", data={
            "ssid": "Manual_Audit_AP",
            "security": "Open",
            "encryption": "None",
            "wps": "Disabled",
            "password_strength": "Weak",
            "captive_portal": "Detected"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Manual_Audit_AP", res.data)
        self.assertIn(b"CRITICAL", res.data)

        profiles = app.load_all_profiles()
        ssids = [p["ssid"] for p in profiles]
        self.assertIn("Manual_Audit_AP", ssids)

    def test_manual_add_empty_ssid_rejected(self):
        """Submitting an empty SSID to manual add should flash an error and reject."""
        with self.client.session_transaction() as sess:
            sess["username"] = "web_tester"

        res = self.client.post("/manual_add", data={
            "ssid": "   ",
            "security": "WPA2"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 200)
        self.assertIn(b"cannot be empty", res.data)

    def test_export_json_and_csv(self):
        """Logged in user can export audit reports as JSON and CSV downloads."""
        with self.client.session_transaction() as sess:
            sess["username"] = "web_tester"

        # Test JSON export
        res_json = self.client.get("/export/json")
        self.assertEqual(res_json.status_code, 200)
        self.assertEqual(res_json.mimetype, "application/json")
        self.assertIn("attachment;filename=wifi_security_report.json", res_json.headers.get("Content-Disposition", ""))
        json_data = json.loads(res_json.data.decode("utf-8"))
        self.assertIn("report_title", json_data)
        self.assertIn("profiles", json_data)

        # Test CSV export
        res_csv = self.client.get("/export/csv")
        self.assertEqual(res_csv.status_code, 200)
        self.assertEqual(res_csv.mimetype, "text/csv")
        self.assertIn("attachment;filename=wifi_security_report.csv", res_csv.headers.get("Content-Disposition", ""))
        self.assertIn(b"SSID,Security,Encryption", res_csv.data)

    def test_delete_profile(self):
        """Logged in user can delete an evaluated profile by SSID."""
        with self.client.session_transaction() as sess:
            sess["username"] = "web_tester"

        res = self.client.post("/delete_profile/TestSandboxAP", follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"removed", res.data)

        profiles = app.load_all_profiles()
        ssids = [p["ssid"] for p in profiles]
        self.assertNotIn("TestSandboxAP", ssids)

    def test_api_detect_auth_guard(self):
        """API detection endpoint requires authentication."""
        # Unauthenticated
        res = self.client.get("/api/detect")
        self.assertEqual(res.status_code, 401)

        # Authenticated
        with self.client.session_transaction() as sess:
            sess["username"] = "web_tester"
        res_auth = self.client.get("/api/detect")
        self.assertEqual(res_auth.status_code, 200)


if __name__ == "__main__":
    unittest.main()
