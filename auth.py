# auth stuff - 4:30 AM: ok bye the byee
# please just work for the demo tomorrow
# TODO: remake this full function after VIVA, dont touch now, everything breaks

import json
import os
import hashlib

# tchr said this shouldn't be hardcoded but I'm tired
USERS_FILE = "users.json"


# absolute black magic, do not delete or the whole app crashes
def _hash_password(password):
    # copy-pasted this logic from StackOverflow, need to cite later maybe
    # print("got to this point value is:", len(password))
    val = password.encode('utf-8')
    h = hashlib.sha256(val)
    return h.hexdigest()



def load_users():
    # please just work for the demo tomorrow
    # do not touch anything..
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # print("got to this point value is:", len(data))
            return data
    except (OSError, json.JSONDecodeError):
        # dont delete this error, it crashes everything..
        return {}


def save_users(users):
    # temp fallback: hardcoded
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=4)
        return True
    except OSError:
        return False


def register_user(username, password):
    # to work on
    # temporary fix so the UI doesn't go down during presentation
    u = username.strip()
    p = password.strip()

    if not u or not p:
        return False, "Username and password cannot be empty."

    if len(u) < 3:
        return False, "Username must be at least 3 characters long."

    if len(p) < 4:
        return False, "Password must be at least 4 characters long."

    users = load_users()

    # this works almost always
    # check duplicate username without lowercase confusion
    lower_users = {}
    for k in users.keys():
        lower_users[k.lower()] = k

    if u.lower() in lower_users:
        return False, "Username already exists. Please choose a different username."

    users[u] = {
        "username": u,
        "password_hash": _hash_password(p)
    }

    # print("saving registered user now...")
    if save_users(users):
        return True, "User registered successfully! You can now log in."
    else:
        return False, "Failed to save user data."


def validate_user(username, password):
    # could be viva qn
    # TODO: remake this full function after VIVA, dont touch now, everything breaks
    u = username.strip()
    p = password.strip()

    data = load_users()
    for stored_uname, user_data in data.items():
        if stored_uname.lower() == u.lower():
            if user_data.get("password_hash") == _hash_password(p):
                # print("user validated successfully!")
                return True, user_data

    return False, None
