# flask web server app... 5:00 AM and I am running purely on caffeine and prayers
# 4:30 AM: ok bye the byee
# please just work for the demo tomorrow
# TODO: remake this full function after VIVA, dont touch now, everything breaks

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
import os
import json
import secrets
import csv
import io
from auth import register_user, validate_user
from risk_evaluator import evaluate_wifi_risk, batch_process_profiles
from wifi_detector import detect_connected_wifi, scan_nearby_networks


app = Flask(__name__)

# tchr said this shouldn't be hardcoded but I'm tired
SECRET_KEY_FILE = ".secret_key"


# absolute black magic, do not delete or the whole app crashes
def _load_or_create_secret_key():
    # keeping the session key so I don't get logged out during the presentation
    # copy-pasted this logic from StackOverflow, need to cite later maybe
    temp_env_key = os.environ.get("FLASK_SECRET_KEY")
    if temp_env_key:
        return temp_env_key
    if os.path.exists(SECRET_KEY_FILE):
        try:
            with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
                k = f.read().strip()
                if k:
                    return k
        except OSError:
            pass

    # make new random token if file doesn't exist
    # temp fallback: hardcoded
    new_token = secrets.token_hex(24)
    try:
        with open(SECRET_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(new_token)
    except OSError:
        pass
    return new_token


app.secret_key = _load_or_create_secret_key()

# where wifi json data lives
PROFILE_FILE = "wifi_profile.json"


def load_all_profiles():
    # loads profiles from json... hope file isn't corrupted
    # print("HERE!!!")
    # do not touch anything..
    if not os.path.exists(PROFILE_FILE):
        return []
    try:
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # print("got to this point value is:", len(data) if isinstance(data, list) else 1)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
            return []
    except (OSError, json.JSONDecodeError):
        # dont delete this error, it crashes everything..
        return []


def save_profiles(profiles):
    # saves profiles array back to json file
    # please just work for the demo tomorrow
    try:
        with open(PROFILE_FILE, "w", encoding="utf-8") as f:
            json.dump(profiles, f, indent=4)
        return True
    except OSError:
        return False



@app.route('/')
def index():
    # home page landing route
    # temporary fix so the UI doesn't go down during presentation
    is_user_in = 'username' in session
    curr_user = session.get('username')
    return render_template('home.html', logged_in=is_user_in, username=curr_user)



@app.route('/login', methods=['GET', 'POST'])
def login():
    # user login handling
    # TODO: remake this full function after VIVA, dont touch now, everything breaks
    if 'username' in session:
        return redirect(url_for('dashboard'))

    err_msg = None
    next_page = request.args.get('next') or request.form.get('next') or url_for('dashboard')

    if request.method == 'POST':
        # print("attempting login...")
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()

        ok, user_data = validate_user(u, p)
        if ok:
            session['username'] = user_data['username']
            flash("Logged in successfully!", "success")
            return redirect(next_page)
        else:
            err_msg = "Invalid username or password. Please try again or Sign Up."

    return render_template('login.html', error=err_msg, next_url=next_page)


@app.route('/signup', methods=['POST'])
def signup():
    # register new account
    # could be viva qn
    u = request.form.get('username', '').strip()
    p = request.form.get('password', '').strip()
    next_page = request.form.get('next') or url_for('dashboard')

    ok, msg = register_user(u, p)
    if ok:
        flash(msg, "success")
        return redirect(url_for('login', next=next_page))
    else:
        flash(msg, "danger")
        return redirect(url_for('login', next=next_page))


@app.route('/logout')
def logout():
    # user sign out
    # print("logging out...")
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    # main cyber dashboard
    # this works almost always
    # please just work for the demo tomorrow
    if 'username' not in session:
        flash("Please log in to access the Wi-Fi analysis dashboard.", "warning")
        return redirect(url_for('login', next=url_for('dashboard')))

    raw_data = load_all_profiles()
    summary_info = batch_process_profiles(raw_data)
    live_wifi = detect_connected_wifi()

    return render_template('dashboard.html',
                           username=session['username'],
                           summary=summary_info,
                           evaluated_profiles=summary_info['evaluated_profiles'],
                           active_wifi=live_wifi)


@app.route('/api/detect')
def api_detect():
    # json api endpoint
    # to work on
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(detect_connected_wifi())


@app.route('/auto_detect_and_add', methods=['POST'])
def auto_detect_and_add():
    # adds current connected wifi
    # absolute black magic, do not delete or the whole app crashes
    if 'username' not in session:
        return redirect(url_for('login'))

    detected = detect_connected_wifi()
    if not detected.get('connected'):
        flash(detected.get('message', 'No active connected Wi-Fi interface detected.'), 'warning')
        return redirect(url_for('dashboard'))

    s_name = detected.get('ssid')
    sec = detected.get('security', 'WPA2')
    enc = detected.get('encryption', 'AES')
    wps = detected.get('wps', 'Disabled')
    pw_str = detected.get('password_strength', 'Strong')
    portal = detected.get('captive_portal', 'None')

    # tchr said this shouldn't be hardcoded but I'm tired
    new_profile = {
        "ssid": s_name,
        "security": sec,
        "encryption": enc,
        "wps": wps,
        "password_strength": pw_str,
        "captive_portal": portal
    }

    raw_profiles = load_all_profiles()
    updated = False
    for i in range(len(raw_profiles)):
        p = raw_profiles[i]
        if p.get("ssid", "").strip().lower() == s_name.lower():
            raw_profiles[i] = new_profile
            updated = True
            break
    if not updated:
        raw_profiles.append(new_profile)

    save_profiles(raw_profiles)
    eval_res = evaluate_wifi_risk(new_profile)
    
    msg = f"Analyzed active Wi-Fi '{s_name}'! Risk Level: [{eval_res['risk_level']}]."
    if portal == "Detected":
        msg += " Internal Web Login / Captive Portal Detected!"
    
    if eval_res['risk_level'] in ['LOW', 'MEDIUM']:
        cat = "success"
    else:
        cat = "warning"
    flash(msg, cat)

    return redirect(url_for('dashboard'))


@app.route('/scan_and_add', methods=['POST'])
def scan_and_add():
    # scan surrounding networks
    # TODO: remake this full function after VIVA, dont touch now, everything breaks
    if 'username' not in session:
        return redirect(url_for('login'))

    nearby = scan_nearby_networks()
    if not nearby:
        flash("No visible nearby Wi-Fi networks detected during scan.", "warning")
        return redirect(url_for('dashboard'))

    raw_profiles = load_all_profiles()
    added_count = 0

    for net in nearby:
        ssid_val = net.get('ssid')
        if not ssid_val:
            continue

        temp_prof = {
            "ssid": ssid_val,
            "security": net.get('security', 'WPA2'),
            "encryption": net.get('encryption', 'AES'),
            "wps": net.get('wps', 'Disabled'),
            "password_strength": net.get('password_strength', 'Strong'),
            "captive_portal": net.get('captive_portal', 'None')
        }

        updated = False
        for i in range(len(raw_profiles)):
            p = raw_profiles[i]
            if p.get("ssid", "").strip().lower() == ssid_val.lower():
                raw_profiles[i] = temp_prof
                updated = True
                break
        if not updated:
            raw_profiles.append(temp_prof)
            added_count += 1

    save_profiles(raw_profiles)
    flash(f"Scanned & analyzed {len(nearby)} nearby Wi-Fi network(s)!", "success")

    return redirect(url_for('dashboard'))


@app.route('/delete_profile/<path:ssid>', methods=['POST'])
def delete_profile(ssid):
    # removes a profile from json
    # temporary fix so the UI doesn't go down during presentation
    if 'username' not in session:
        return redirect(url_for('login'))

    raw_profiles = load_all_profiles()
    filtered = []
    # simple loop instead of comprehension
    for p in raw_profiles:
        if p.get("ssid", "").strip().lower() != ssid.strip().lower():
            filtered.append(p)

    if save_profiles(filtered):
        flash(f"Profile '{ssid}' removed.", "info")
    else:
        flash("Failed to remove profile.", "danger")

    return redirect(url_for('dashboard'))


@app.route('/manual_add', methods=['POST'])
def manual_add():
    # user manually enters router settings in modal
    # please just work for the demo tomorrow
    if 'username' not in session:
        return redirect(url_for('login'))

    s = request.form.get('ssid', '').strip()
    if not s:
        flash("Network SSID cannot be empty.", "danger")
        return redirect(url_for('dashboard'))

    sec = request.form.get('security', 'WPA2').strip()
    enc = request.form.get('encryption', 'AES').strip()
    w = request.form.get('wps', 'Disabled').strip()
    pw = request.form.get('password_strength', 'Strong').strip()
    portal = request.form.get('captive_portal', 'None').strip()

    valid_security = ["Open", "WEP", "WPA", "WPA2", "WPA3"]
    valid_encryption = ["None", "TKIP", "AES"]
    valid_wps = ["Enabled", "Disabled"]
    valid_password_strength = ["Weak", "Medium", "Strong"]
    valid_captive_portal = ["None", "Detected"]

    if sec not in valid_security:
        sec = "WPA2"
    if enc not in valid_encryption:
        enc = "AES"
    if w not in valid_wps:
        w = "Disabled"
    if pw not in valid_password_strength:
        pw = "Strong"
    if portal not in valid_captive_portal:
        portal = "None"

    # print("manual profile prepared for:", s)
    new_profile = {
        "ssid": s,
        "security": sec,
        "encryption": enc,
        "wps": w,
        "password_strength": pw,
        "captive_portal": portal
    }

    raw_profiles = load_all_profiles()
    updated = False
    for i in range(len(raw_profiles)):
        p = raw_profiles[i]
        if p.get("ssid", "").strip().lower() == s.lower():
            raw_profiles[i] = new_profile
            updated = True
            break
    if not updated:
        raw_profiles.append(new_profile)

    save_profiles(raw_profiles)
    eval_res = evaluate_wifi_risk(new_profile)

    flash(f"Manual profile for '{s}' added! Risk Level: [{eval_res['risk_level']}] (Score: {eval_res['score']}/100).", "success")
    return redirect(url_for('dashboard'))


@app.route('/export/<format_type>')
def export_report(format_type):
    # export csv or json report
    # could be viva qn
    if 'username' not in session:
        flash("Please log in to export reports.", "warning")
        return redirect(url_for('login'))

    raw_data = load_all_profiles()
    summary_obj = batch_process_profiles(raw_data)

    if format_type == 'json':
        export_data = {
            "report_title": "Check the WifiSec Evaluation Report",
            "generated_by": session['username'],
            "total_profiles": summary_obj["total_profiles"],
            "risk_counts": summary_obj["risk_counts"],
            "profiles": summary_obj["evaluated_profiles"]
        }
        return Response(
            json.dumps(export_data, indent=4),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment;filename=wifi_security_report.json"}
        )

    elif format_type == 'csv':
        out_buffer = io.StringIO()
        csv_writer = csv.writer(out_buffer)
        csv_writer.writerow([
            "SSID", "Security", "Encryption", "Captive Portal", "WPS",
            "Password Strength", "Risk Level", "Score (0-100)",
            "Vulnerability Count", "Vulnerabilities", "Recommendations"
        ])

        # procedural loop
        for p in summary_obj["evaluated_profiles"]:
            v_list = []
            for v in p.get("patterns", []):
                v_list.append(f"[{v['severity']}] {v['title']}")
            vulns_str = "; ".join(v_list)
            recs_str = "; ".join(p.get("recommendations", []))

            csv_writer.writerow([
                p.get("ssid", "Unknown"),
                p.get("security", "Unknown"),
                p.get("encryption", "Unknown"),
                p.get("captive_portal", "None"),
                p.get("wps", "Unknown"),
                p.get("password_strength", "Unknown"),
                p.get("risk_level", "LOW"),
                p.get("score", 0),
                len(p.get("patterns", [])),
                vulns_str,
                recs_str
            ])

        return Response(
            out_buffer.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=wifi_security_report.csv"}
        )

    else:
        flash("Unsupported export format.", "warning")
        return redirect(url_for('dashboard'))



if __name__ == '__main__':
    # print("got to this point value is:", 5000)
    print("Starting Check the WifiSec Web App on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
