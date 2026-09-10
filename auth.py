"""
User Authentication Module for Wi-Fi Security Profiler.
Handles user signup, login validation, and persistence via users.json.
"""

import json
import os
import hashlib

USERS_FILE = "users.json"

def _hash_password(password):
    """Hash password using SHA-256 for secure storage."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def load_users():
    """Load existing users from JSON file."""
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

def save_users(users):
    """Save users dictionary to JSON file."""
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=4)
        return True
    except OSError:
        return False

def register_user(username, password):
    """
    Registers a new user with username and password.
    Returns (success: bool, message: str)
    """
    username = username.strip()
    password = password.strip()

    if not username or not password:
        return False, "Username and password cannot be empty."

    if len(username) < 3:
        return False, "Username must be at least 3 characters long."

    if len(password) < 4:
        return False, "Password must be at least 4 characters long."

    users = load_users()

    # Check case-insensitive duplicate username
    lower_users = {k.lower(): k for k in users.keys()}
    if username.lower() in lower_users:
        return False, "Username already exists. Please choose a different username."

    users[username] = {
        "username": username,
        "password_hash": _hash_password(password)
    }

    if save_users(users):
        return True, "User registered successfully! You can now log in."
    else:
        return False, "Failed to save user data."

def validate_user(username, password):
    """
    Validates login credentials.
    Returns (success: bool, user_info: dict or None)
    """
    username = username.strip()
    password = password.strip()

    users = load_users()
    for stored_uname, user_data in users.items():
        if stored_uname.lower() == username.lower():
            if user_data.get("password_hash") == _hash_password(password):
                return True, user_data

    return False, None
