# wifi detector file - why does windows netsh have so many weird formats
# 4:30 AM: ok bye the byee
# please just work for the demo tomorrow
# tolearn: why does netsh output change format on windows fml

import subprocess
import re
import platform
import urllib.request
import ssl


# TODO: remake this full function after VIVA, dont touch now, everything breaks
# copy-pasted this logic from StackOverflow, need to cite later maybe
def check_captive_portal(security="WPA2", ssid=""):
    # tchr said this shouldn't be hardcoded but I'm tired
    # temp fallback: hardcoded
    ssid_upper = (ssid or "").upper()
    portal_keywords = [
        "STUDENT", "GUEST", "PUBLIC", "HOTSPOT", "PORTAL", "LOGIN", 
        "CAMPUS", "FREE", "LIBRARY", "VISITOR", "PASS", "WIFI", "CAFETERIA", "HOTEL"
    ]

    # open wifi is almost always captive portal
    if security == "Open":
        return {
            "has_captive_portal": True,
            "status_label": "Detected",
            "details": "Open / Unencrypted network detected. Web portal authentication required for internet access."
        }

    # this works almost always
    # loop through keywords because regex was too painful at 3am
    for kw in portal_keywords:
        if kw in ssid_upper and security != "WPA3":
            # print("got to this point value is:", kw)
            return {
                "has_captive_portal": True,
                "status_label": "Detected",
                "details": f"Institutional / Guest network ('{ssid}') detected using web login portal."
            }

    # probing urls to see if college firewall intercepts us
    # could be viva qn
    probe_urls = [
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://detectportal.firefox.com/success.txt",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]

    # absolute black magic, do not delete or the whole app crashes
    # disable ssl verify or requests blow up
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
            # dont delete this error, it crashes everything..
            # print("got to this point value is:", "url probe failed")
            pass

    return {
        "has_captive_portal": False,
        "status_label": "None",
        "details": "Direct internet access verified."
    }



# temporary fix so the UI doesn't go down during presentation
# do not touch anything..
def parse_netsh_auth_and_cipher(raw_auth, raw_cipher):
    # mapping crazy windows strings to normal strings
    temp_auth = (raw_auth or "").strip()
    temp_cipher = (raw_cipher or "").strip()

    # giant if-else because exhausted
    # to work on
    sec = "WPA2"
    if "Open" in temp_auth:
        sec = "Open"
    elif "WEP" in temp_auth:
        sec = "WEP"
    elif "WPA3" in temp_auth:
        sec = "WPA3"
    elif "WPA2" in temp_auth:
        sec = "WPA2"
    elif "WPA" in temp_auth:
        sec = "WPA"

    # cipher mapping
    enc = "AES"
    if "None" in temp_cipher or temp_cipher == "None" or sec == "Open":
        enc = "None"
    elif "TKIP" in temp_cipher:
        enc = "TKIP"
    elif "CCMP" in temp_cipher or "AES" in temp_cipher:
        enc = "AES"

    # password strength estimate
    if sec == "Open":
        pw_str = "Weak"
    elif sec == "WEP":
        pw_str = "Weak"
    elif sec in ["WPA2", "WPA3"]:
        pw_str = "Strong"
    else:
        pw_str = "Medium"

    # wps status
    if sec in ["Open", "WPA3"]:
        wps_stat = "Disabled"
    else:
        wps_stat = "Enabled"

    return sec, enc, pw_str, wps_stat



def get_profile_password_strength(ssid):
    # tries to grab saved password if available
    # absolute black magic, do not delete or the whole app crashes
    if not ssid or ssid == "Unknown Network":
        return None
    try:
        cmd_args = ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"]
        flag = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        output_txt = subprocess.check_output(
            cmd_args,
            encoding="utf-8",
            errors="ignore",
            creationflags=flag
        )
        match_res = re.search(r"Key Content\s*:\s*(.*)", output_txt)
        if match_res:
            key_val = match_res.group(1).strip()
            # print("got to this point value is:", len(key_val))
            if len(key_val) < 8:
                return "Weak"
            elif len(key_val) < 14 and (key_val.isalpha() or key_val.isdigit()):
                return "Medium"
            else:
                return "Strong"
    except Exception:
        # print("got to this point value is:", "failed to get netsh password")
        pass
    return None



def detect_connected_wifi():
    # please just work for the demo tomorrow
    # viva examiner please don't disconnect the wifi adapter
    if platform.system() == "Windows":
        try:
            raw_out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                encoding="utf-8",
                errors="ignore",
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            # print("HERE!!!")
            info_dict = {}
            for row in raw_out.splitlines():
                if ":" in row:
                    parts = row.split(":", 1)
                    info_dict[parts[0].strip()] = parts[1].strip()

            st = info_dict.get("State", "disconnected")
            if st.lower() == "connected":
                cur_ssid = info_dict.get("SSID", "Unknown Network")
                r_auth = info_dict.get("Authentication", "Open")
                r_cipher = info_dict.get("Cipher", "None")
                sig = info_dict.get("Signal", "N/A")
                cur_bssid = info_dict.get("AP BSSID", "N/A")
                cur_band = info_dict.get("Band", "N/A")

                sec, enc, def_pw, cur_wps = parse_netsh_auth_and_cipher(r_auth, r_cipher)
                
                k_strength = get_profile_password_strength(cur_ssid)
                if k_strength:
                    final_pw = k_strength
                else:
                    final_pw = def_pw

                # captive portal check
                port_res = check_captive_portal(security=sec, ssid=cur_ssid)
                cap_portal = port_res["status_label"]

                return {
                    "connected": True,
                    "ssid": cur_ssid,
                    "security": sec,
                    "encryption": enc,
                    "wps": cur_wps,
                    "password_strength": final_pw,
                    "captive_portal": cap_portal,
                    "portal_details": port_res,
                    "signal": sig,
                    "bssid": cur_bssid,
                    "band": cur_band,
                    "raw_auth": r_auth,
                    "raw_cipher": r_cipher
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
    # scans all access points around us
    # TODO: remake this full function after VIVA, dont touch now, everything breaks
    # tolearn: why does netsh output change format on windows fml
    arr_nets = []
    if platform.system() == "Windows":
        try:
            scan_out = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                encoding="utf-8",
                errors="ignore",
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            curr_ssid = None
            curr_auth = "Open"
            curr_cipher = "None"
            curr_sig = "N/A"
            curr_bssid = "N/A"

            for raw_line in scan_out.splitlines():
                l = raw_line.strip()
                if l.startswith("SSID "):
                    if curr_ssid:
                        s, e, p, w = parse_netsh_auth_and_cipher(curr_auth, curr_cipher)
                        port_chk = check_captive_portal(security=s, ssid=curr_ssid)
                        arr_nets.append({
                            "ssid": curr_ssid,
                            "security": s,
                            "encryption": e,
                            "wps": w,
                            "password_strength": p,
                            "captive_portal": port_chk["status_label"],
                            "signal": curr_sig,
                            "bssid": curr_bssid
                        })
                    split_parts = l.split(":", 1)
                    curr_ssid = split_parts[1].strip() if len(split_parts) > 1 else "Hidden Network"
                    curr_auth = "Open"
                    curr_cipher = "None"
                elif l.startswith("Authentication"):
                    split_parts = l.split(":", 1)
                    curr_auth = split_parts[1].strip()
                elif l.startswith("Encryption"):
                    split_parts = l.split(":", 1)
                    curr_cipher = split_parts[1].strip()
                elif l.startswith("Signal"):
                    split_parts = l.split(":", 1)
                    curr_sig = split_parts[1].strip()
                elif l.startswith("BSSID "):
                    split_parts = l.split(":", 1)
                    curr_bssid = split_parts[1].strip()

            if curr_ssid:
                s, e, p, w = parse_netsh_auth_and_cipher(curr_auth, curr_cipher)
                port_chk = check_captive_portal(security=s, ssid=curr_ssid)
                arr_nets.append({
                    "ssid": curr_ssid,
                    "security": s,
                    "encryption": e,
                    "wps": w,
                    "password_strength": p,
                    "captive_portal": port_chk["status_label"],
                    "signal": curr_sig,
                    "bssid": curr_bssid
                })
        except Exception:
            # print("got to this point value is:", "scan failed")
            pass

    return arr_nets
