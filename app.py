"""
Flask Web Application for Wi-Fi Security Profiler
Provides login/signup screen, automated connected Wi-Fi analysis,
nearby network scanning, internal web login / captive portal probing,
and interactive Comprehensive Risk Cards.
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import json
import secrets
from auth import register_user, validate_user
from risk_evaluator import evaluate_wifi_risk, batch_process_profiles
from wifi_detector import detect_connected_wifi, scan_nearby_networks

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
    """Home landing page with comprehensive tool description and analysis CTA."""
    return render_template('home.html', logged_in=('username' in session), username=session.get('username'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login with redirection back to original target if provided."""
    if 'username' in session:
        return redirect(url_for('dashboard'))

    error = None
    next_url = request.args.get('next') or request.form.get('next') or url_for('dashboard')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        valid, user_data = validate_user(username, password)
        if valid:
            session['username'] = user_data['username']
            flash("Logged in successfully!", "success")
            return redirect(next_url)
        else:
            error = "Invalid username or password. Please try again or Sign Up."

    return render_template('login.html', error=error, next_url=next_url)


@app.route('/signup', methods=['POST'])
def signup():
    """Handles new user registration."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    next_url = request.form.get('next') or url_for('dashboard')

    ok, message = register_user(username, password)
    if ok:
        flash(message, "success")
        return redirect(url_for('login', next=next_url))
    else:
        flash(message, "danger")
        return redirect(url_for('login', next=next_url))


@app.route('/logout')
def logout():
    """Logs out current user."""
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """Main dashboard displaying live Wi-Fi status, scan controls, and evaluated security profile cards."""
    if 'username' not in session:
        flash("Please log in to access the Wi-Fi analysis dashboard.", "warning")
        return redirect(url_for('login', next=url_for('dashboard')))

    raw_profiles = load_all_profiles()
    summary = batch_process_profiles(raw_profiles)
    active_wifi = detect_connected_wifi()

    return render_template('dashboard.html',
                           username=session['username'],
                           summary=summary,
                           evaluated_profiles=summary['evaluated_profiles'],
                           active_wifi=active_wifi)


@app.route('/api/detect')
def api_detect():
    """API endpoint returning detected Wi-Fi data as JSON."""
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(detect_connected_wifi())


@app.route('/auto_detect_and_add', methods=['POST'])
def auto_detect_and_add():
    """Auto-detects connected Wi-Fi network & captive portal status, adding it to security profiles."""
    if 'username' not in session:
        return redirect(url_for('login'))

    detected = detect_connected_wifi()
    if not detected.get('connected'):
        flash(detected.get('message', 'No active connected Wi-Fi interface detected.'), 'warning')
        return redirect(url_for('dashboard'))

    ssid = detected.get('ssid')
    security = detected.get('security', 'WPA2')
    encryption = detected.get('encryption', 'AES')
    wps = detected.get('wps', 'Disabled')
    password_strength = detected.get('password_strength', 'Strong')
    captive_portal = detected.get('captive_portal', 'None')

    new_profile = {
        "ssid": ssid,
        "security": security,
        "encryption": encryption,
        "wps": wps,
        "password_strength": password_strength,
        "captive_portal": captive_portal
    }

    raw_profiles = load_all_profiles()
    updated = False
    for i, p in enumerate(raw_profiles):
        if p.get("ssid", "").strip().lower() == ssid.lower():
            raw_profiles[i] = new_profile
            updated = True
            break
    if not updated:
        raw_profiles.append(new_profile)

    save_profiles(raw_profiles)
    eval_res = evaluate_wifi_risk(new_profile)
    
    msg = f"Analyzed active Wi-Fi '{ssid}'! Risk Level: [{eval_res['risk_level']}]."
    if captive_portal == "Detected":
        msg += " Internal Web Login / Captive Portal Detected!"
    flash(msg, "success" if eval_res['risk_level'] in ['LOW', 'MEDIUM'] else "warning")

    return redirect(url_for('dashboard'))


@app.route('/scan_and_add', methods=['POST'])
def scan_and_add():
    """Scans all visible nearby Wi-Fi networks and adds them to evaluated profiles."""
    if 'username' not in session:
        return redirect(url_for('login'))

    nearby = scan_nearby_networks()
    if not nearby:
        flash("No visible nearby Wi-Fi networks detected during scan.", "warning")
        return redirect(url_for('dashboard'))

    raw_profiles = load_all_profiles()
    added_count = 0

    for net in nearby:
        ssid = net.get('ssid')
        if not ssid:
            continue

        new_profile = {
            "ssid": ssid,
            "security": net.get('security', 'WPA2'),
            "encryption": net.get('encryption', 'AES'),
            "wps": net.get('wps', 'Disabled'),
            "password_strength": net.get('password_strength', 'Strong'),
            "captive_portal": net.get('captive_portal', 'None')
        }

        updated = False
        for i, p in enumerate(raw_profiles):
            if p.get("ssid", "").strip().lower() == ssid.lower():
                raw_profiles[i] = new_profile
                updated = True
                break
        if not updated:
            raw_profiles.append(new_profile)
            added_count += 1

    save_profiles(raw_profiles)
    flash(f"Scanned & analyzed {len(nearby)} nearby Wi-Fi network(s)!", "success")

    return redirect(url_for('dashboard'))


@app.route('/delete_profile/<path:ssid>', methods=['POST'])
def delete_profile(ssid):
    """Deletes a Wi-Fi profile by SSID."""
    if 'username' not in session:
        return redirect(url_for('login'))

    raw_profiles = load_all_profiles()
    filtered = [p for p in raw_profiles if p.get("ssid", "").strip().lower() != ssid.strip().lower()]

    if save_profiles(filtered):
        flash(f"Profile '{ssid}' removed.", "info")
    else:
        flash("Failed to remove profile.", "danger")

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    print("Starting Wi-Fi Security Profiler Web App on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
