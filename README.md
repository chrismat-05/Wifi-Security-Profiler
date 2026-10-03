# Wi-Fi Security Profiler

An interactive Wi-Fi Security Analysis tool featuring hardware auto-detection, internal web login / captive portal probing, rule-based vulnerability pattern detection, risk level classification, SHA-256 user authentication, and a modern dark cybersecurity web interface built with Flask.

---

## Key Features

### Hardware Auto-Detection & Captive Portal Probing
- **Live Connected Wi-Fi Detection**: Queries active wireless interface for SSID, Authentication, Cipher, Signal Strength, BSSID, and Band.
- **Captive Portal / Internal Web Login Detection**: Probes standard network endpoints to detect internal splash pages or web login redirections (e.g. open networks requiring captive portal authentication).
- **Nearby Wi-Fi Scanner**: Scans and displays visible nearby Wi-Fi access points.

### Advanced Analysis & Web Interface
- **Vulnerability Pattern Engine**: Identifies specific security vulnerabilities (Open/Unencrypted networks, Captive Portal credential risks, obsolete WEP protocol, legacy TKIP ciphers, WPS PIN brute-force risks, and weak passwords).
- **Risk Level Classification**: Computes a 0–100 risk score and assigns a risk category (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Actionable Recommendations**: Generates tailored security hardening steps for each profile.
- **User Signup & Authentication**: Multi-user registration and login with SHA-256 password hashing.
- **Cybersecurity Web UI**: Responsive dark theme dashboard with glassmorphism cards and neon risk badges.
- **Dual Interface**: Run via terminal CLI (`main.py`) or web application (`app.py`).

---

## Project Structure

```text
Wifi Security Profiler/
│── app.py                # Flask Web Server & API Routes
│── auth.py               # Signup, Login & Hashing Module
│── wifi_detector.py      # Real-time Wi-Fi & Captive Portal Detection
│── risk_evaluator.py     # Vulnerability Pattern & Risk Engine
│── main.py               # Terminal CLI Application
│── requirements.txt      # Python dependencies
│── .gitignore            # Git ignore rules
│── wifi_profile.json     # Saved Wi-Fi Profiles database
│── static/
│   └── css/
│       └── style.css     # Cybersecurity Dark Theme CSS
└── templates/
    ├── home.html         # Landing page & tool overview template
    ├── login.html        # Sign In & Sign Up template
    └── dashboard.html    # Dashboard & Risk Cards template
```

---

## Getting Started

### 1. Prerequisites
- Python 3.8 or higher installed on your machine.

### 2. Installation
Clone this repository and install dependencies:
```bash
git clone <your-repository-url>
cd "Wifi Security Profiler"
pip install -r requirements.txt
```

### 3. Running the Web Application
```bash
python app.py
```
Open your browser and navigate to `http://127.0.0.1:5000`.

### 4. Running the CLI Application
```bash
python main.py
```

---

## License
Distributed under the MIT License.
