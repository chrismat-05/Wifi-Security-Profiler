"""
Wi-Fi Security Profiler - CLI Interface (Phase 1 & Phase 2)
Supports profile collection, input validation, data structures,
pattern identification, risk level classification, and file persistence.
"""

import json
import os
from risk_evaluator import evaluate_wifi_risk, batch_process_profiles

PROFILE_FILE = "wifi_profile.json"


def display_menu(title, options):
    """Display a numbered menu of options."""
    if title:
        print(f"\n{title}")

    for number, option in enumerate(options, start=1):
        print(f"{number}. {option}")


def get_non_empty_input(prompt):
    """Get input that is not empty or only whitespace."""
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Error: Input cannot be empty. Please try again.")


def get_choice(prompt, options):
    """Get a valid numbered choice from a list of options."""
    while True:
        display_menu("", options)
        choice = input(prompt).strip()

        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(options):
                return options[choice_num - 1]
            print("Invalid choice. Please select a valid number from the menu.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def collect_wifi_profile():
    """Collect and validate core Wi-Fi profile parameters (Phase 1)."""
    security_types = ["Open", "WEP", "WPA", "WPA2", "WPA3"]
    encryption_types = ["None", "TKIP", "AES"]
    wps_options = ["Enabled", "Disabled"]
    password_strength_options = ["Weak", "Medium", "Strong"]

    print("\n----------------------------------------")
    print("      ENTER WI-FI PROFILE DETAILS")
    print("----------------------------------------")
    print("Note: Do not enter actual Wi-Fi passwords.")
    print("Only provide a classification of its strength.")

    ssid = get_non_empty_input("\nEnter SSID (Network Name): ")

    security = get_choice("Select Security Type: ", security_types)
    encryption = get_choice("Select Encryption Type: ", encryption_types)
    wps = get_choice("Select WPS Status: ", wps_options)
    password_strength = get_choice("Select Password Strength: ", password_strength_options)

    wifi_profile = {
        "ssid": ssid,
        "security": security,
        "encryption": encryption,
        "wps": wps,
        "password_strength": password_strength
    }

    return wifi_profile


def display_evaluated_profile(eval_res):
    """Display the Wi-Fi profile with Phase 2 risk classification & pattern analysis."""
    print("\n========================================")
    print(f" PROFILE & RISK ANALYSIS: {eval_res['ssid']}")
    print("========================================")
    print(f"SSID                : {eval_res['ssid']}")
    print(f"Security Type       : {eval_res['security']}")
    print(f"Encryption          : {eval_res['encryption']}")
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
    """Load profiles list from JSON file."""
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
    """Append new Wi-Fi profile to JSON storage."""
    existing_profiles = load_all_profiles()
    
    # Check if SSID already exists, update or append
    updated = False
    for i, prof in enumerate(existing_profiles):
        if prof.get("ssid", "").strip().lower() == new_profile["ssid"].strip().lower():
            existing_profiles[i] = new_profile
            updated = True
            break
            
    if not updated:
        existing_profiles.append(new_profile)

    try:
        with open(PROFILE_FILE, "w", encoding="utf-8") as file:
            json.dump(existing_profiles, file, indent=4)
        print(f"Profile for '{new_profile['ssid']}' saved successfully to {PROFILE_FILE}.")
    except OSError as error:
        print(f"Unable to save profile: {error}")


def main():
    """Main execution loop for CLI Profiler (Phases 1 & 2)."""
    print("========================================")
    print("       WI-FI SECURITY PROFILER")
    print("       PHASE 1 & 2 CLI INTERFACE")
    print("========================================")

    while True:
        options = [
            "Add & Profile New Wi-Fi Network",
            "View All Profiles & Risk Summary",
            "Exit CLI"
        ]
        choice = get_choice("\nMain Menu - Select an option: ", options)

        if choice == "Add & Profile New Wi-Fi Network":
            raw_profile = collect_wifi_profile()
            eval_res = evaluate_wifi_risk(raw_profile)
            display_evaluated_profile(eval_res)
            
            save_ans = input("Save this profile to storage? (y/n): ").strip().lower()
            if save_ans == 'y':
                save_profile_to_list(raw_profile)

        elif choice == "View All Profiles & Risk Summary":
            profiles = load_all_profiles()
            if not profiles:
                print("\nNo saved Wi-Fi profiles found.")
            else:
                summary = batch_process_profiles(profiles)
                print("\n========================================")
                print("      AGGREGATE RISK REPORT SUMMARY")
                print("========================================")
                print(f"Total Wi-Fi Networks Profiled: {summary['total_profiles']}")
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