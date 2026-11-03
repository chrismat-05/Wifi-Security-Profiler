# main terminal interface... 4:30 AM: ok bye the byee
# please just work for the demo tomorrow
# TODO: remake this full function after VIVA, dont touch now, everything breaks

import json
import os
from risk_evaluator import evaluate_wifi_risk, batch_process_profiles
from wifi_detector import detect_connected_wifi, scan_nearby_networks

# tchr said this shouldn't be hardcoded but I'm tired
PROFILE_FILE = "wifi_profile.json"


# menu printing function
def display_menu(title, options):
    if title:
        print(f"\n{title}")

    # temporary fix so the UI doesn't go down during presentation
    for number, option in enumerate(options, start=1):
        print(f"{number}. {option}")



# input validation so examiner doesn't crash on empty string
def get_non_empty_input(prompt):
    # do not touch anything..
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Error: Input cannot be empty. Please try again.")


def get_choice(prompt, options):
    # copy-pasted this logic from StackOverflow, need to cite later maybe
    # could be viva qn
    while True:
        display_menu("", options)
        choice = input(prompt).strip()

        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(options):
                return options[choice_num - 1]
            print("Invalid choice. Please select a valid number from the menu.")
        except ValueError:
            # dont delete this error, it crashes everything..
            print("Invalid input. Please enter a number.")


def collect_wifi_profile():
    # manual input flow
    # to work on
    # temp fallback: hardcoded
    security_types = ["Open", "WEP", "WPA", "WPA2", "WPA3"]
    encryption_types = ["None", "TKIP", "AES"]
    captive_portal_options = ["None", "Detected"]
    wps_options = ["Enabled", "Disabled"]
    password_strength_options = ["Weak", "Medium", "Strong"]

    print("\n----------------------------------------")
    print("      ENTER WI-FI PROFILE DETAILS")
    print("----------------------------------------")

    ssid = get_non_empty_input("\nEnter SSID (Network Name): ")

    security = get_choice("Select Security Type: ", security_types)
    encryption = get_choice("Select Encryption Type: ", encryption_types)
    captive_portal = get_choice("Internal Web Login / Captive Portal Status: ", captive_portal_options)
    wps = get_choice("Select WPS Status: ", wps_options)
    password_strength = get_choice("Select Password Strength: ", password_strength_options)

    # this works almost always
    wifi_profile = {
        "ssid": ssid,
        "security": security,
        "encryption": encryption,
        "captive_portal": captive_portal,
        "wps": wps,
        "password_strength": password_strength
    }

    return wifi_profile


# absolute black magic, do not delete or the whole app crashes
def display_evaluated_profile(eval_res):
    # print("got to this point value is:", eval_res.get('ssid'))
    print("\n========================================")
    print(f" PROFILE & RISK ANALYSIS: {eval_res['ssid']}")
    print("========================================")
    print(f"SSID                : {eval_res['ssid']}")
    print(f"Security Type       : {eval_res['security']}")
    print(f"Encryption          : {eval_res['encryption']}")
    print(f"Internal Web Login  : {eval_res.get('captive_portal', 'None')}")
    print(f"WPS Status          : {eval_res['wps']}")
    print(f"Password Strength   : {eval_res['password_strength']}")
    print("----------------------------------------")
    print(f"RISK LEVEL          : [{eval_res['risk_level']}] (Score: {eval_res['score']}/100)")
    print("----------------------------------------")

    print("\n[IDENTIFIED PATTERNS & VULNERABILITIES]")
    if eval_res['patterns']:
        for p in eval_res['patterns']:
            print(f" - [{p['severity']}] {p['title']}: {p['description']}")
    else:
        print(" - No severe vulnerability patterns detected.")

    print("\n[RECOMMENDATIONS]")
    for rec in eval_res['recommendations']:
        print(f" -> {rec}")

    print("========================================\n")



def load_all_profiles():
    # loading profiles json
    if not os.path.exists(PROFILE_FILE):
        return []
    try:
        with open(PROFILE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
            return []
    except (OSError, json.JSONDecodeError):
        return []


def save_profile_to_list(new_profile):
    # saves single profile into json
    # please just work for the demo tomorrow
    existing_profiles = load_all_profiles()
    
    updated = False
    for i in range(len(existing_profiles)):
        prof = existing_profiles[i]
        if prof.get("ssid", "").strip().lower() == new_profile["ssid"].strip().lower():
            existing_profiles[i] = new_profile
            updated = True
            break
            
    if not updated:
        existing_profiles.append(new_profile)

    try:
        with open(PROFILE_FILE, "w", encoding="utf-8") as file:
            json.dump(existing_profiles, file, indent=4)
    except OSError:
        pass



def main():
    # main loop
    # TODO: remake this full function after VIVA, dont touch now, everything breaks
    print("========================================")
    print("       WI-FI SECURITY PROFILER")
    print("========================================")

    while True:
        options = [
            "Auto-Detect & Analyze Connected Wi-Fi",
            "Scan & Analyze Nearby Wi-Fi Networks",
            "Manually Analyze Wi-Fi Details",
            "View All Analyzed Risk Summaries",
            "Exit CLI"
        ]
        choice = get_choice("\nMain Menu - Select an option: ", options)

        if choice == "Auto-Detect & Analyze Connected Wi-Fi":
            print("\nScanning active network interface & probing for captive portal...")
            detected = detect_connected_wifi()
            if not detected.get("connected"):
                print(f"Detection Result: {detected.get('message', 'No connected Wi-Fi found.')}")
            else:
                print(f"Connected Wi-Fi Detected! SSID: {detected['ssid']} (Signal: {detected['signal']})")
                print(f"Internal Web Login / Captive Portal: {detected['captive_portal']}")
                raw_profile = {
                    "ssid": detected['ssid'],
                    "security": detected['security'],
                    "encryption": detected['encryption'],
                    "wps": detected['wps'],
                    "password_strength": detected['password_strength'],
                    "captive_portal": detected['captive_portal']
                }
                eval_res = evaluate_wifi_risk(raw_profile)
                display_evaluated_profile(eval_res)
                save_profile_to_list(raw_profile)

        elif choice == "Scan & Analyze Nearby Wi-Fi Networks":
            print("\nScanning visible nearby Wi-Fi networks...")
            nearby = scan_nearby_networks()
            if not nearby:
                print("No visible Wi-Fi networks found.")
            else:
                print(f"Found {len(nearby)} visible nearby Wi-Fi network(s):")
                for net in nearby:
                    eval_res = evaluate_wifi_risk(net)
                    display_evaluated_profile(eval_res)
                    save_profile_to_list(net)

        elif choice == "Manually Analyze Wi-Fi Details":
            raw_profile = collect_wifi_profile()
            eval_res = evaluate_wifi_risk(raw_profile)
            display_evaluated_profile(eval_res)
            save_profile_to_list(raw_profile)

        elif choice == "View All Analyzed Risk Summaries":
            profiles = load_all_profiles()
            if not profiles:
                print("\nNo analyzed Wi-Fi profiles found.")
            else:
                summary = batch_process_profiles(profiles)
                print("\n========================================")
                print("      AGGREGATE RISK REPORT SUMMARY")
                print("========================================")
                print(f"Total Wi-Fi Networks Analyzed: {summary['total_profiles']}")
                for risk_cat, count in summary['risk_counts'].items():
                    print(f" - {risk_cat:10s} : {count}")
                print("========================================")

                for eval_res in summary['evaluated_profiles']:
                    display_evaluated_profile(eval_res)

        elif choice == "Exit CLI":
            print("\nExiting Wi-Fi Security Profiler CLI. Goodbye!")
            break


if __name__ == "__main__":
    main()
