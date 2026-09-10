"""
Flask Web Application for Wi-Fi Security Profiler (Phase 2)
Provides login/signup screen, dashboard with profile management,
and interactive Comprehensive Risk Cards with cybersecurity design.
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import json
import secrets
from auth import register_user, validate_user
from risk_evaluator import evaluate_wifi_risk, batch_process_profiles

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

PROFILE_FILE = "wifi_profile.json"


def load_all_profiles():
    """Load raw Wi-Fi profiles list from JSON file."""
    if not os.path.exists(PROFILE_FILE):
        return []
    try:
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
            return []
    except (OSError, json.JSONDecodeError):
        return []


def save_profiles(profiles):
    """Save profiles list to JSON file."""
    try:
        with open(PROFILE_FILE, "w", encoding="utf-8") as f:
            json.dump(profiles, f, indent=4)
        return True
    except OSError:
        return False


@app.route('/')
def index():
    """Redirect to dashboard if logged in, else login page."""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if 'username' in session:
        return redirect(url_for('dashboard'))

    error = None
    success = None

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        valid, user_data = validate_user(username, password)
        if valid:
            session['username'] = user_data['username']
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password. Please try again or Sign Up."

    return render_template('login.html', error=error, success=success)


@app.route('/signup', methods=['POST'])
def signup():
    """Handles new user registration."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    ok, message = register_user(username, password)
    if ok:
        flash(message, "success")
    else:
        flash(message, "danger")

    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs out current user."""
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    """Main dashboard displaying profile creation form and evaluated profiles."""
    if 'username' not in session:
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for('login'))

    raw_profiles = load_all_profiles()
    summary = batch_process_profiles(raw_profiles)

    return render_template('dashboard.html',
                           username=session['username'],
                           summary=summary,
                           evaluated_profiles=summary['evaluated_profiles'])


@app.route('/add_profile', methods=['POST'])
def add_profile():
    """Handles adding a new Wi-Fi profile and validating fields (Phase 1 & Phase 2)."""
    if 'username' not in session:
        return redirect(url_for('login'))

    ssid = request.form.get('ssid', '').strip()
    security = request.form.get('security', '').strip()
    encryption = request.form.get('encryption', '').strip()
    wps = request.form.get('wps', '').strip()
    password_strength = request.form.get('password_strength', '').strip()

    # Validation
    if not ssid:
        flash("SSID cannot be empty.", "danger")
        return redirect(url_for('dashboard'))

    valid_security = ["Open", "WEP", "WPA", "WPA2", "WPA3"]
    valid_encryption = ["None", "TKIP", "AES"]
    valid_wps = ["Enabled", "Disabled"]
    valid_pw = ["Weak", "Medium", "Strong"]

    if security not in valid_security or encryption not in valid_encryption or wps not in valid_wps or password_strength not in valid_pw:
        flash("Invalid selection provided. Please choose valid options.", "danger")
        return redirect(url_for('dashboard'))

    new_profile = {
        "ssid": ssid,
        "security": security,
        "encryption": encryption,
        "wps": wps,
        "password_strength": password_strength
    }

    raw_profiles = load_all_profiles()
    
    # Overwrite if same SSID exists or append
    updated = False
    for i, p in enumerate(raw_profiles):
        if p.get("ssid", "").strip().lower() == ssid.lower():
            raw_profiles[i] = new_profile
            updated = True
            break
    if not updated:
        raw_profiles.append(new_profile)

    if save_profiles(raw_profiles):
        flash(f"Wi-Fi profile '{ssid}' evaluated and saved successfully!", "success")
    else:
        flash("Failed to save profile to disk.", "danger")

    return redirect(url_for('dashboard'))


@app.route('/delete_profile/<path:ssid>', methods=['POST'])
def delete_profile(ssid):
    """Deletes a Wi-Fi profile by SSID."""
    if 'username' not in session:
        return redirect(url_for('login'))

    raw_profiles = load_all_profiles()
    filtered = [p for p in raw_profiles if p.get("ssid", "").strip().lower() != ssid.strip().lower()]

    if save_profiles(filtered):
        flash(f"Profile '{ssid}' deleted successfully.", "info")
    else:
        flash("Failed to delete profile.", "danger")

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    print("Starting Wi-Fi Security Profiler Web App on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
