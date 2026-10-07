"""
Wi-Fi Detector Module for Wi-Fi Security Profiler.
Detects active connected Wi-Fi interfaces, identifies internal web login portals / captive portals,
and scans visible nearby networks using system utilities.
"""

import subprocess
import re
import platform
import urllib.request
import ssl


def check_captive_portal(security="WPA2", ssid=""):
    """
    Probes HTTP endpoints and evaluates network heuristics to detect internal web login / captive portals.
    Open networks and institutional/guest Wi-Fi networks default to captive portal detection.
    """
    # Keyword heuristics for networks known to use web portals
    ssid_upper = (ssid or "").upper()
    portal_keywords = [
        "STUDENT", "GUEST", "PUBLIC", "HOTSPOT", "PORTAL", "LOGIN", 
        "CAMPUS", "FREE", "LIBRARY", "VISITOR", "PASS", "WIFI", "CAFETERIA", "HOTEL"
    ]

    # Heuristic 1: Open / Unencrypted networks almost universally utilize Web Login / Captive Portals
    if security == "Open":
        return {
            "has_captive_portal": True,
            "status_label": "Detected",
            "details": "Open / Unencrypted network detected. Web portal authentication required for internet access."
        }

    # Heuristic 2: SSID keyword matching
    for kw in portal_keywords:
        if kw in ssid_upper and security != "WPA3":
            return {
                "has_captive_portal": True,
                "status_label": "Detected",
                "details": f"Institutional / Guest network ('{ssid}') detected using web login portal."
            }

    # Live HTTP probe detection
    probe_urls = [
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://detectportal.firefox.com/success.txt",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    for url in probe_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            res = urllib.request.urlopen(req, timeout=2.5, context=context)
            status = res.getcode()
            final_url = res.geturl()
            content = res.read().decode("utf-8", errors="ignore")

            if "generate_204" in url:
                if status != 204 or final_url != url:
                    return {
                        "has_captive_portal": True,
                        "status_label": "Detected",
                        "details": f"Internal web login redirection detected (Redirected to: {final_url})"
                    }
            elif "firefox" in url:
                if status != 200 or content.strip() != "success" or final_url != url:
                    return {
                        "has_captive_portal": True,
                        "status_label": "Detected",
                        "details": "Web login portal detected intercepting HTTP traffic."
                    }
            elif "msftconnecttest" in url:
                if status != 200 or "Microsoft Connect Test" not in content or final_url != url:
                    return {
                        "has_captive_portal": True,
                        "status_label": "Detected",
                        "details": "Internal splash page intercepted network request."
                    }
        except Exception:
            pass

    return {
        "has_captive_portal": False,
        "status_label": "None",
        "details": "Direct internet access verified."
    }


def parse_netsh_auth_and_cipher(raw_auth, raw_cipher):
    """Maps raw Windows auth and cipher strings to profiler standardized values."""
    raw_auth = (raw_auth or "").strip()
    raw_cipher = (raw_cipher or "").strip()

    # Map Security / Auth
    security = "WPA2"
    if "Open" in raw_auth:
        security = "Open"
    elif "WEP" in raw_auth:
        security = "WEP"
    elif "WPA3" in raw_auth:
        security = "WPA3"
    elif "WPA2" in raw_auth:
        security = "WPA2"
    elif "WPA" in raw_auth:
        security = "WPA"

    # Map Encryption / Cipher
    encryption = "AES"
    if "None" in raw_cipher or raw_cipher == "None" or security == "Open":
        encryption = "None"
    elif "TKIP" in raw_cipher:
        encryption = "TKIP"
    elif "CCMP" in raw_cipher or "AES" in raw_cipher:
        encryption = "AES"

    # Password Strength inference
    if security == "Open":
        password_strength = "Weak"
    elif security == "WEP":
        password_strength = "Weak"
    elif security in ["WPA2", "WPA3"]:
        password_strength = "Strong"
    else:
        password_strength = "Medium"

    # Default WPS status inference
    wps_status = "Disabled" if security in ["Open", "WPA3"] else "Enabled"

    return security, encryption, password_strength, wps_status


def get_profile_password_strength(ssid):
    """Inspects stored Windows key for a given profile SSID to assess password strength."""
    if not ssid or ssid == "Unknown Network":
        return None
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
            encoding="utf-8",
            errors="ignore",
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        )
        key_match = re.search(r"Key Content\s*:\s*(.*)", output)
        if key_match:
            key = key_match.group(1).strip()
            if len(key) < 8:
                return "Weak"
            elif len(key) < 14 and (key.isalpha() or key.isdigit()):
                return "Medium"
            else:
                return "Strong"
    except Exception:
        pass
    return None


def detect_connected_wifi():
    """
    Detects the active connected Wi-Fi interface and evaluates internal web login / captive portal status.
    """
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                encoding="utf-8",
                errors="ignore",
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            info = {}
            for line in output.splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    info[parts[0].strip()] = parts[1].strip()

            state = info.get("State", "disconnected")
            if state.lower() == "connected":
                ssid = info.get("SSID", "Unknown Network")
                raw_auth = info.get("Authentication", "Open")
                raw_cipher = info.get("Cipher", "None")
                signal = info.get("Signal", "N/A")
                bssid = info.get("AP BSSID", "N/A")
                band = info.get("Band", "N/A")

                security, encryption, default_pw_strength, wps_status = parse_netsh_auth_and_cipher(raw_auth, raw_cipher)
                
                key_strength = get_profile_password_strength(ssid)
                password_strength = key_strength if key_strength else default_pw_strength

                # Check Captive Portal / Internal Web Login status
                portal_info = check_captive_portal(security=security, ssid=ssid)
                captive_portal = portal_info["status_label"]

                return {
                    "connected": True,
                    "ssid": ssid,
                    "security": security,
                    "encryption": encryption,
                    "wps": wps_status,
                    "password_strength": password_strength,
                    "captive_portal": captive_portal,
                    "portal_details": portal_info,
                    "signal": signal,
                    "bssid": bssid,
                    "band": band,
                    "raw_auth": raw_auth,
                    "raw_cipher": raw_cipher
                }
            else:
                return {
                    "connected": False,
                    "message": "Wi-Fi adapter is disconnected or not connected to any access point."
                }
        except Exception as e:
            return {
                "connected": False,
                "error": f"Error running Wi-Fi detection: {str(e)}"
            }

    return {
        "connected": False,
        "message": "Automatic hardware detection is supported on Windows systems."
    }


def scan_nearby_networks():
    """
    Scans for visible nearby Wi-Fi networks using netsh mode=bssid.
    """
    networks = []
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                encoding="utf-8",
                errors="ignore",
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            current_ssid = None
            current_auth = "Open"
            current_cipher = "None"
            current_signal = "N/A"
            current_bssid = "N/A"

            for line in output.splitlines():
                line = line.strip()
                if line.startswith("SSID "):
                    if current_ssid:
                        sec, enc, pw_str, wps = parse_netsh_auth_and_cipher(current_auth, current_cipher)
                        portal_info = check_captive_portal(security=sec, ssid=current_ssid)
                        networks.append({
                            "ssid": current_ssid,
                            "security": sec,
                            "encryption": enc,
                            "wps": wps,
                            "password_strength": pw_str,
                            "captive_portal": portal_info["status_label"],
                            "signal": current_signal,
                            "bssid": current_bssid
                        })
                    parts = line.split(":", 1)
                    current_ssid = parts[1].strip() if len(parts) > 1 else "Hidden Network"
                    current_auth = "Open"
                    current_cipher = "None"
                elif line.startswith("Authentication"):
                    parts = line.split(":", 1)
                    current_auth = parts[1].strip()
                elif line.startswith("Encryption"):
                    parts = line.split(":", 1)
                    current_cipher = parts[1].strip()
                elif line.startswith("Signal"):
                    parts = line.split(":", 1)
                    current_signal = parts[1].strip()
                elif line.startswith("BSSID "):
                    parts = line.split(":", 1)
                    current_bssid = parts[1].strip()

            if current_ssid:
                sec, enc, pw_str, wps = parse_netsh_auth_and_cipher(current_auth, current_cipher)
                portal_info = check_captive_portal(security=sec, ssid=current_ssid)
                networks.append({
                    "ssid": current_ssid,
                    "security": sec,
                    "encryption": enc,
                    "wps": wps,
                    "password_strength": pw_str,
                    "captive_portal": portal_info["status_label"],
                    "signal": current_signal,
                    "bssid": current_bssid
                })
        except Exception:
            pass

    return networks
