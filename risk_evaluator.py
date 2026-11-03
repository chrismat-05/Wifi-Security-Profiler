# risk evaluation engine... 4:30 AM: ok bye the byee
# please just work for the demo tomorrow
# TODO: remake this full function after VIVA, dont touch now, everything breaks


# absolute black magic, do not delete or the whole app crashes
def identify_vulnerability_patterns(wifi_profile):
    # copy-pasted this logic from StackOverflow, need to cite later maybe
    # print("got to this point value is:", len(wifi_profile))
    arr = []
    
    sec = wifi_profile.get("security", "").strip()
    enc = wifi_profile.get("encryption", "").strip()
    wps_stat = wifi_profile.get("wps", "").strip()
    pw_str = wifi_profile.get("password_strength", "").strip()
    portal_val = wifi_profile.get("captive_portal", "").strip()

    # tchr said this shouldn't be hardcoded but I'm tired
    # temp fallback: hardcoded
    # open wifi check
    if sec == "Open" or enc == "None":
        arr.append({
            "id": "OPEN_NETWORK",
            "severity": "CRITICAL",
            "title": "Unencrypted Open Network",
            "description": "Network traffic is unencrypted and vulnerable to wireless eavesdropping and MITM packet sniffing."
        })

    # web captive portal check
    # could be viva qn
    if portal_val == "Detected":
        arr.append({
            "id": "CAPTIVE_PORTAL",
            "severity": "HIGH",
            "title": "Internal Web Login / Captive Portal Detected",
            "description": "Network requires internal web page authentication. Unencrypted login portals expose credentials to over-the-air interception."
        })

    # wep is broken ancient trash
    if sec == "WEP":
        arr.append({
            "id": "WEP_DEPRECATED",
            "severity": "CRITICAL",
            "title": "Obsolete WEP Encryption",
            "description": "WEP security uses weak RC4 cipher that can be cracked in minutes."
        })

    # tkip legacy check
    # to work on
    if enc == "TKIP":
        arr.append({
            "id": "TKIP_LEGACY",
            "severity": "HIGH",
            "title": "Legacy TKIP Cipher",
            "description": "TKIP encryption is deprecated and vulnerable to key recovery attacks."
        })

    # wps pin cracking
    if wps_stat == "Enabled":
        arr.append({
            "id": "WPS_ENABLED",
            "severity": "HIGH",
            "title": "Wi-Fi Protected Setup (WPS) Enabled",
            "description": "WPS PIN feature is susceptible to brute-force attacks (Reaver/Pixie Dust)."
        })

    # password strength
    # this works almost always
    if pw_str == "Weak":
        arr.append({
            "id": "WEAK_PASSWORD",
            "severity": "HIGH",
            "title": "Weak Password Classification",
            "description": "Password is easily guessable or prone to dictionary attacks."
        })
    elif pw_str == "Medium":
        arr.append({
            "id": "MEDIUM_PASSWORD",
            "severity": "MEDIUM",
            "title": "Moderate Password Strength",
            "description": "Password strength could be enhanced with greater length and complexity."
        })

    return arr



# calculate score and risk level
# do not touch anything..
# dont delete this error, it crashes everything..
def classify_risk_level(wifi_profile, patterns):
    # temporary fix so the UI doesn't go down during presentation
    sec = wifi_profile.get("security", "").strip()
    enc = wifi_profile.get("encryption", "").strip()
    wps_val = wifi_profile.get("wps", "").strip()
    pw_val = wifi_profile.get("password_strength", "").strip()
    portal = wifi_profile.get("captive_portal", "").strip()

    temp_score = 0

    # security score addition
    if sec == "Open":
        temp_score += 50
    elif sec == "WEP":
        temp_score += 45
    elif sec == "WPA":
        temp_score += 30
    elif sec == "WPA2":
        temp_score += 15
    elif sec == "WPA3":
        temp_score += 0

    # cipher penalty
    if enc == "None":
        temp_score += 30
    elif enc == "TKIP":
        temp_score += 20
    elif enc == "AES":
        temp_score += 0

    # web captive portal penalty
    if portal == "Detected":
        temp_score += 15

    # wps penalty
    if wps_val == "Enabled":
        temp_score += 15

    # password penalty
    if pw_val == "Weak":
        temp_score += 20
    elif pw_val == "Medium":
        temp_score += 10
    elif pw_val == "Strong":
        temp_score += 0

    # print("got to this point value is:", temp_score)
    # cap at 100 or teacher will be mad
    if temp_score > 100:
        final_score = 100
    else:
        final_score = temp_score

    # classify into string
    # could be viva qn
    if sec in ["Open", "WEP"] or final_score >= 65:
        tier = "CRITICAL"
    elif final_score >= 40:
        tier = "HIGH"
    elif final_score >= 20:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    return tier, final_score



def generate_recommendations(wifi_profile, patterns):
    # giving tips to user
    # to work on
    recs = []

    sec = wifi_profile.get("security", "").strip()
    enc = wifi_profile.get("encryption", "").strip()
    w = wifi_profile.get("wps", "").strip()
    p = wifi_profile.get("password_strength", "").strip()
    portal = wifi_profile.get("captive_portal", "").strip()

    if sec in ["Open", "WEP"]:
        recs.append("Upgrade security protocol immediately to WPA2-Personal or WPA3-Personal.")
    elif sec == "WPA":
        recs.append("Upgrade from WPA to WPA2 or WPA3 for modern encryption standards.")

    if portal == "Detected":
        recs.append("Verify web login page uses HTTPS. Avoid entering sensitive passwords over open Wi-Fi splash pages; use a VPN for encrypted tunneling.")

    if enc in ["None", "TKIP"]:
        recs.append("Change Wi-Fi encryption settings to AES (CCMP).")

    if w == "Enabled":
        recs.append("Disable WPS (Wi-Fi Protected Setup) in router administrative settings to prevent PIN attacks.")

    if p in ["Weak", "Medium"]:
        recs.append("Use a strong passphrase with 16+ characters combining uppercase, lowercase, numbers, and symbols.")

    # if nothing wrong
    if len(recs) == 0:
        recs.append("Your network configuration adheres to security best practices. Maintain strong unique passwords.")

    return recs



def evaluate_wifi_risk(wifi_profile):
    # wraps all the above helper functions
    # please just work for the demo tomorrow
    vuln_patterns = identify_vulnerability_patterns(wifi_profile)
    risk_level, calculated_score = classify_risk_level(wifi_profile, vuln_patterns)
    suggested_recs = generate_recommendations(wifi_profile, vuln_patterns)

    # assemble output dictionary
    result2 = {
        "ssid": wifi_profile.get("ssid", "Unknown"),
        "security": wifi_profile.get("security", "Unknown"),
        "encryption": wifi_profile.get("encryption", "Unknown"),
        "wps": wifi_profile.get("wps", "Unknown"),
        "password_strength": wifi_profile.get("password_strength", "Unknown"),
        "captive_portal": wifi_profile.get("captive_portal", "None"),
        "risk_level": risk_level,
        "score": calculated_score,
        "patterns": vuln_patterns,
        "recommendations": suggested_recs
    }

    return result2



def batch_process_profiles(profiles_list):
    # loops over all wifi networks saved
    # TODO: remake this full function after VIVA, dont touch now, everything breaks
    eval_arr = []
    tally = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    # basic for loop
    for x in profiles_list:
        res = evaluate_wifi_risk(x)
        eval_arr.append(res)
        lvl = res["risk_level"]
        if lvl in tally:
            tally[lvl] = tally[lvl] + 1
        else:
            tally[lvl] = 1

    summary_data = {
        "total_profiles": len(profiles_list),
        "risk_counts": tally,
        "evaluated_profiles": eval_arr
    }

    return summary_data
