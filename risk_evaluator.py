"""
Risk Evaluator Module for Wi-Fi Security Profiler.
Processes Wi-Fi profile data through conditions and loops to identify
vulnerability patterns (including captive portals / internal web logins),
classify risk levels, and generate actionable security recommendations.
"""

def identify_vulnerability_patterns(wifi_profile):
    """
    Identifies security risk patterns from Wi-Fi profile dictionary.
    Returns a list of pattern description dictionaries.
    """
    patterns = []
    
    security = wifi_profile.get("security", "").strip()
    encryption = wifi_profile.get("encryption", "").strip()
    wps = wifi_profile.get("wps", "").strip()
    password_strength = wifi_profile.get("password_strength", "").strip()
    captive_portal = wifi_profile.get("captive_portal", "").strip()

    # Pattern 1: Unencrypted / Open Network
    if security == "Open" or encryption == "None":
        patterns.append({
            "id": "OPEN_NETWORK",
            "severity": "CRITICAL",
            "title": "Unencrypted Open Network",
            "description": "Network traffic is unencrypted and vulnerable to wireless eavesdropping and MITM packet sniffing."
        })

    # Pattern 2: Captive Portal / Internal Web Login
    if captive_portal == "Detected":
        patterns.append({
            "id": "CAPTIVE_PORTAL",
            "severity": "HIGH",
            "title": "Internal Web Login / Captive Portal Detected",
            "description": "Network requires internal web page authentication. Unencrypted login portals expose credentials to over-the-air interception."
        })

    # Pattern 3: WEP Protocol (Obsolete & Severely Broken)
    if security == "WEP":
        patterns.append({
            "id": "WEP_DEPRECATED",
            "severity": "CRITICAL",
            "title": "Obsolete WEP Encryption",
            "description": "WEP security uses weak RC4 cipher that can be cracked in minutes."
        })

    # Pattern 4: Legacy TKIP Encryption
    if encryption == "TKIP":
        patterns.append({
            "id": "TKIP_LEGACY",
            "severity": "HIGH",
            "title": "Legacy TKIP Cipher",
            "description": "TKIP encryption is deprecated and vulnerable to key recovery attacks."
        })

    # Pattern 5: WPS Enabled Vulnerability
    if wps == "Enabled":
        patterns.append({
            "id": "WPS_ENABLED",
            "severity": "HIGH",
            "title": "Wi-Fi Protected Setup (WPS) Enabled",
            "description": "WPS PIN feature is susceptible to brute-force attacks (Reaver/Pixie Dust)."
        })

    # Pattern 6: Weak or Medium Password Strength
    if password_strength == "Weak":
        patterns.append({
            "id": "WEAK_PASSWORD",
            "severity": "HIGH",
            "title": "Weak Password Classification",
            "description": "Password is easily guessable or prone to dictionary attacks."
        })
    elif password_strength == "Medium":
        patterns.append({
            "id": "MEDIUM_PASSWORD",
            "severity": "MEDIUM",
            "title": "Moderate Password Strength",
            "description": "Password strength could be enhanced with greater length and complexity."
        })

    return patterns


def classify_risk_level(wifi_profile, patterns):
    """
    Classifies overall risk level into CRITICAL, HIGH, MEDIUM, or LOW based on conditions.
    Calculates a numerical risk score (0-100).
    """
    security = wifi_profile.get("security", "").strip()
    encryption = wifi_profile.get("encryption", "").strip()
    wps = wifi_profile.get("wps", "").strip()
    password_strength = wifi_profile.get("password_strength", "").strip()
    captive_portal = wifi_profile.get("captive_portal", "").strip()

    score = 0

    # Base score by Security protocol
    if security == "Open":
        score += 50
    elif security == "WEP":
        score += 45
    elif security == "WPA":
        score += 30
    elif security == "WPA2":
        score += 15
    elif security == "WPA3":
        score += 0

    # Encryption penalty
    if encryption == "None":
        score += 30
    elif encryption == "TKIP":
        score += 20
    elif encryption == "AES":
        score += 0

    # Captive Portal penalty
    if captive_portal == "Detected":
        score += 15

    # WPS penalty
    if wps == "Enabled":
        score += 15

    # Password penalty
    if password_strength == "Weak":
        score += 20
    elif password_strength == "Medium":
        score += 10
    elif password_strength == "Strong":
        score += 0

    # Cap score at 100
    score = min(100, score)

    # Determine Risk Category
    if security in ["Open", "WEP"] or score >= 65:
        risk_level = "CRITICAL"
    elif score >= 40:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_level, score


def generate_recommendations(wifi_profile, patterns):
    """
    Generates actionable security recommendations based on identified patterns.
    """
    recommendations = []

    security = wifi_profile.get("security", "").strip()
    encryption = wifi_profile.get("encryption", "").strip()
    wps = wifi_profile.get("wps", "").strip()
    password_strength = wifi_profile.get("password_strength", "").strip()
    captive_portal = wifi_profile.get("captive_portal", "").strip()

    if security in ["Open", "WEP"]:
        recommendations.append("Upgrade security protocol immediately to WPA2-Personal or WPA3-Personal.")
    elif security == "WPA":
        recommendations.append("Upgrade from WPA to WPA2 or WPA3 for modern encryption standards.")

    if captive_portal == "Detected":
        recommendations.append("Verify web login page uses HTTPS. Avoid entering sensitive passwords over open Wi-Fi splash pages; use a VPN for encrypted tunneling.")

    if encryption in ["None", "TKIP"]:
        recommendations.append("Change Wi-Fi encryption settings to AES (CCMP).")

    if wps == "Enabled":
        recommendations.append("Disable WPS (Wi-Fi Protected Setup) in router administrative settings to prevent PIN attacks.")

    if password_strength in ["Weak", "Medium"]:
        recommendations.append("Use a strong passphrase with 16+ characters combining uppercase, lowercase, numbers, and symbols.")

    if not recommendations:
        recommendations.append("Your network configuration adheres to security best practices. Maintain strong unique passwords.")

    return recommendations


def evaluate_wifi_risk(wifi_profile):
    """
    Main evaluation function for a single Wi-Fi profile dictionary.
    Returns a comprehensive risk assessment dictionary.
    """
    patterns = identify_vulnerability_patterns(wifi_profile)
    risk_level, score = classify_risk_level(wifi_profile, patterns)
    recommendations = generate_recommendations(wifi_profile, patterns)

    result = {
        "ssid": wifi_profile.get("ssid", "Unknown"),
        "security": wifi_profile.get("security", "Unknown"),
        "encryption": wifi_profile.get("encryption", "Unknown"),
        "wps": wifi_profile.get("wps", "Unknown"),
        "password_strength": wifi_profile.get("password_strength", "Unknown"),
        "captive_portal": wifi_profile.get("captive_portal", "None"),
        "risk_level": risk_level,
        "score": score,
        "patterns": patterns,
        "recommendations": recommendations
    }

    return result


def batch_process_profiles(profiles_list):
    """
    Processes a list of Wi-Fi profile dictionaries using loops.
    Returns evaluated profiles and aggregate risk statistics.
    """
    evaluated_list = []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for profile in profiles_list:
        eval_res = evaluate_wifi_risk(profile)
        evaluated_list.append(eval_res)
        level = eval_res["risk_level"]
        counts[level] = counts.get(level, 0) + 1

    summary = {
        "total_profiles": len(profiles_list),
        "risk_counts": counts,
        "evaluated_profiles": evaluated_list
    }

    return summary
