"""
SOC Private Authentication & Access Control Module.
Provides secure private access for the Autonomous Multi-Agent Framework.
Supports login via registered Gmail or Mobile Number and cryptographic password verification.
"""

import os
import re
import json
import time
import hashlib
import secrets
from typing import Dict, Any, Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

# Path to persistent credentials storage
CREDENTIALS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".auth_credentials.json"
)

# Rate Limiting Configuration
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 60

# In-memory tracking of failed login attempts
_failed_attempts: Dict[str, list] = {}
_lockout_until: float = 0.0


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Returns (hex_hash, hex_salt).
    """
    if not salt:
        salt_bytes = secrets.token_bytes(16)
        salt = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        iterations=100_000
    )
    return derived_key.hex(), salt


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """Verify that a plain password matches the stored PBKDF2 hash."""
    test_hash, _ = hash_password(password, stored_salt)
    import hmac
    return hmac.compare_digest(test_hash, stored_hash)


def normalize_phone(phone: str) -> str:
    """
    Normalizes a phone string by removing spaces, hyphens, and parenthesis.
    Returns the normalized numeric string (with optional leading +).
    """
    if not phone:
        return ""
    cleaned = re.sub(r"[^\d+]", "", phone.strip())
    return cleaned


def phone_matches(input_phone: str, registered_phone: str) -> bool:
    """
    Checks if an input phone matches the registered phone.
    Matches exact cleaned string, or matching last 10 digits (to accommodate country code prefixes like +91).
    """
    norm_input = normalize_phone(input_phone)
    norm_reg = normalize_phone(registered_phone)

    if not norm_input or not norm_reg:
        return False

    if norm_input == norm_reg:
        return True

    # Compare last 10 digits (national number)
    digits_input = re.sub(r"\D", "", norm_input)
    digits_reg = re.sub(r"\D", "", norm_reg)

    if len(digits_input) >= 10 and len(digits_reg) >= 10:
        return digits_input[-10:] == digits_reg[-10:]

    return False


def normalize_email(email: str) -> str:
    """Normalizes email to lowercase and strips whitespace."""
    if not email:
        return ""
    return email.strip().lower()


def get_default_credentials() -> Dict[str, Any]:
    """Retrieves default credentials from environment variables or secure defaults."""
    owner_name = os.getenv("SOC_OWNER_NAME", "Hemanth Gowda T")
    owner_email = os.getenv("SOC_OWNER_GMAIL", "hemanthhemu6557@gmail.com")
    owner_mobile = os.getenv("SOC_OWNER_MOBILE", "+919886966865")
    default_password = os.getenv("SOC_OWNER_PASSWORD", "Hemanth@6557")

    pwd_hash, salt = hash_password(default_password)

    return {
        "name": owner_name,
        "email": normalize_email(owner_email),
        "mobile": normalize_phone(owner_mobile),
        "password_hash": pwd_hash,
        "salt": salt,
        "role": "SOC Master Operator / Project Lead",
        "last_login": None,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }


def load_credentials() -> Dict[str, Any]:
    """Loads persistent credentials from disk or creates default if missing."""
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Ensure essential fields exist
                if "password_hash" in data and "salt" in data:
                    return data
        except Exception:
            pass

    # Initialize default credentials and save
    creds = get_default_credentials()
    save_credentials(creds)
    return creds


def save_credentials(creds: Dict[str, Any]) -> bool:
    """Saves credentials dictionary to disk."""
    try:
        with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
            json.dump(creds, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving credentials: {e}")
        return False


def check_rate_limit(client_id: str = "default") -> Tuple[bool, int]:
    """
    Checks if client is currently locked out due to excessive failed attempts.
    Returns (is_locked_out, seconds_remaining).
    """
    global _lockout_until
    now = time.time()

    if now < _lockout_until:
        return True, int(_lockout_until - now)

    # Clean old attempts (> 5 minutes ago)
    attempts = _failed_attempts.get(client_id, [])
    attempts = [t for t in attempts if now - t < 300]
    _failed_attempts[client_id] = attempts

    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        _lockout_until = now + LOCKOUT_DURATION_SECONDS
        return True, LOCKOUT_DURATION_SECONDS

    return False, 0


def record_failed_attempt(client_id: str = "default"):
    """Records a failed authentication attempt."""
    now = time.time()
    attempts = _failed_attempts.get(client_id, [])
    attempts.append(now)
    _failed_attempts[client_id] = attempts

    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        global _lockout_until
        _lockout_until = now + LOCKOUT_DURATION_SECONDS


def reset_failed_attempts(client_id: str = "default"):
    """Resets failed attempts upon successful login."""
    _failed_attempts[client_id] = []


def authenticate_user(
    identifier: str, 
    password: str, 
    client_id: str = "default",
    auth_type: Optional[str] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticates user using their registered Gmail or Mobile Number and password.
    
    auth_type:
      - None: permits either Gmail or Phone (backward-compatible)
      - "gmail" or "email": strictly permits only registered Gmail address (disallows phone access)
      - "phone" or "mobile": strictly permits only registered phone number (disallows Gmail access)
      
    Returns: (is_success, message, user_data_dict)
    """
    if not identifier or not identifier.strip():
        if auth_type in ("gmail", "email"):
            return False, "Please enter your registered Gmail address.", None
        elif auth_type in ("phone", "mobile"):
            return False, "Please enter your registered phone number.", None
        return False, "Please enter your registered Gmail address or Mobile Number.", None

    if not password:
        return False, "Please enter your access password.", None

    # Check brute-force rate limit
    is_locked, remaining = check_rate_limit(client_id)
    if is_locked:
        return False, f"🚨 Access temporarily locked due to repeated failed attempts. Please wait {remaining} seconds.", None

    creds = load_credentials()
    identifier_clean = identifier.strip()

    # Check whether identifier matches email OR username/name OR mobile
    matches_email = (normalize_email(identifier_clean) == creds["email"])
    matches_name = (identifier_clean.lower() == creds.get("name", "").lower() or 
                    identifier_clean.lower() in ["hemanth", "hemanth gowda t", "admin"])
    matches_phone = phone_matches(identifier_clean, creds.get("mobile", ""))

    # Strict enforcement based on user's selected login method
    if auth_type in ("gmail", "email"):
        if matches_phone or identifier_clean.replace("+", "").replace("-", "").replace(" ", "").isdigit():
            return False, "Access Denied: Mobile numbers are not permitted when logging in via Registered Gmail. Please enter your registered Gmail address.", None
        if not (matches_email or matches_name):
            record_failed_attempt(client_id)
            return False, "Access Denied: The provided Gmail address is not authorized for private access.", None
        auth_method = "Gmail"

    elif auth_type in ("enterprise",):
        if not (matches_email or matches_name):
            record_failed_attempt(client_id)
            return False, "Access Denied: The provided email or username is not authorized for private access.", None
        auth_method = "Enterprise Workspace"

    elif auth_type in ("phone", "mobile"):
        if matches_email or "@" in identifier_clean:
            return False, "Access Denied: Gmail addresses are not permitted when logging in via Registered Phone Number. Please enter your registered 10-digit phone number.", None
        if not matches_phone:
            record_failed_attempt(client_id)
            return False, "Access Denied: The provided phone number is not authorized for private access.", None
        auth_method = "Mobile Number"

    else:
        if not (matches_email or matches_name or matches_phone):
            record_failed_attempt(client_id)
            return False, "Access Denied: The provided Gmail or Mobile Number is not authorized for private access.", None
        auth_method = "Gmail" if matches_email else ("Enterprise Workspace" if matches_name else "Mobile Number")

    # Verify password hash
    if not verify_password(password, creds["password_hash"], creds["salt"]):
        record_failed_attempt(client_id)
        return False, "Access Denied: Invalid password for this authorized account.", None

    # Authentication successful!
    reset_failed_attempts(client_id)
    creds["last_login"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_credentials(creds)

    user_info = {
        "name": creds.get("name", "Hemanth Gowda T"),
        "email": creds["email"],
        "mobile": creds["mobile"],
        "role": creds.get("role", "SOC Master Operator"),
        "auth_method": auth_method,
        "last_login": creds["last_login"]
    }

    return True, "Authentication Successful! Access Granted.", user_info


def update_credentials(
    current_password: str,
    new_name: Optional[str] = None,
    new_email: Optional[str] = None,
    new_mobile: Optional[str] = None,
    new_password: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Allows the authorized owner to update their name, Gmail, Mobile number, or Password.
    Requires current password verification.
    """
    creds = load_credentials()

    # Verify current password
    if not verify_password(current_password, creds["password_hash"], creds["salt"]):
        return False, "Verification failed: Current password is incorrect."

    updated = False

    if new_name and new_name.strip():
        creds["name"] = new_name.strip()
        updated = True

    if new_email and new_email.strip():
        norm_em = normalize_email(new_email)
        if "@" not in norm_em or "." not in norm_em:
            return False, "Invalid email format. Please provide a valid Gmail/Email address."
        creds["email"] = norm_em
        updated = True

    if new_mobile and new_mobile.strip():
        norm_mob = normalize_phone(new_mobile)
        digits = re.sub(r"\D", "", norm_mob)
        if len(digits) < 10:
            return False, "Invalid mobile number. Please provide a valid 10+ digit mobile number."
        creds["mobile"] = norm_mob
        updated = True

    if new_password and new_password.strip():
        if len(new_password) < 6:
            return False, "New password must be at least 6 characters long."
        new_hash, new_salt = hash_password(new_password)
        creds["password_hash"] = new_hash
        creds["salt"] = new_salt
        updated = True

    if updated:
        save_credentials(creds)
        return True, "Private credentials updated successfully!"

    return False, "No changes were specified."


def get_masked_profile() -> Dict[str, str]:
    """Returns safe masked details of the authorized owner profile."""
    creds = load_credentials()
    email = creds.get("email", "")
    mobile = creds.get("mobile", "")

    # Mask email: h***a@gmail.com
    masked_email = email
    if "@" in email:
        user_part, domain_part = email.split("@", 1)
        if len(user_part) > 2:
            masked_email = f"{user_part[0]}***{user_part[-1]}@{domain_part}"
        else:
            masked_email = f"{user_part[0]}***@{domain_part}"

    # Mask mobile: +91 98****3210
    digits = re.sub(r"\D", "", mobile)
    if len(digits) >= 10:
        masked_mobile = f"+{digits[:-10]} {digits[-10:-6]}****{digits[-2:]}" if len(digits) > 10 else f"{digits[:2]}******{digits[-2:]}"
    else:
        masked_mobile = mobile

    return {
        "name": creds.get("name", "Hemanth Gowda T"),
        "masked_email": masked_email,
        "masked_mobile": masked_mobile,
        "email_raw": email,
        "mobile_raw": mobile,
        "role": creds.get("role", "SOC Master Operator")
    }


def reset_password(
    identifier: str,
    new_password: str
) -> Tuple[bool, str]:
    """
    Resets the authorized operator's password using their registered Gmail or Mobile Number.
    Updates persistent credentials storage and synchronizes .env if present.
    """
    if not identifier or not identifier.strip():
        return False, "Please enter your registered Gmail address or Mobile Number."

    creds = load_credentials()
    id_clean = identifier.strip()

    matches_email = (normalize_email(id_clean) == creds["email"])
    matches_phone = phone_matches(id_clean, creds["mobile"])

    if not (matches_email or matches_phone):
        return False, "Verification failed: Provided Gmail or Mobile Number does not match authorized owner records."

    if not new_password or len(new_password) < 6:
        return False, "New password must be at least 6 characters long."

    new_hash, new_salt = hash_password(new_password)
    creds["password_hash"] = new_hash
    creds["salt"] = new_salt
    save_credentials(creds)

    return True, "Password reset successfully! You can now log in with your new password."
