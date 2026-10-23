"""
OTP Dispatch & Notification Service for Autonomous Multi-Agent Framework.
Provides real-world OTP transmission to registered Gmail (via SMTP) and Mobile (via SMS Gateway).
"""

import os
import re
import smtplib
import urllib.request
import urllib.parse
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()


def get_smtp_config() -> Dict[str, Any]:
    """Loads SMTP configuration from environment variables."""
    return {
        "server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "user": os.getenv("SMTP_USER", "").strip(),
        "password": os.getenv("SMTP_PASSWORD", "").replace(" ", "").strip(),
        "sender_name": os.getenv("SMTP_SENDER_NAME", "SOC Multi-Agent Security Gateway")
    }


def get_sms_config() -> Dict[str, Any]:
    """Loads SMS gateway configuration from environment variables."""
    return {
        "fast2sms_key": os.getenv("FAST2SMS_API_KEY", "").strip(),
        "fast2sms_otp_id": os.getenv("FAST2SMS_OTP_ID", "").strip(),
        "twilio_sid": os.getenv("TWILIO_ACCOUNT_SID", "").strip(),
        "twilio_token": os.getenv("TWILIO_AUTH_TOKEN", "").strip(),
        "twilio_from": os.getenv("TWILIO_FROM_NUMBER", "").strip()
    }


def send_email_otp(recipient_email: str, otp_code: str, recipient_name: str = "Hemanth Gowda T") -> Tuple[bool, str]:
    """
    Sends a real OTP verification email to the user's Gmail address via SMTP.
    Requires SMTP_USER and SMTP_PASSWORD (Google App Password) in .env.
    """
    smtp_cfg = get_smtp_config()
    sender_email = smtp_cfg["user"]
    sender_password = smtp_cfg["password"]

    if not sender_email or not sender_password:
        return False, "Gmail SMTP is not yet configured. Please set SMTP_USER and SMTP_PASSWORD (Google App Password) in .env to deliver real emails."

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🛡️ [SOC Security] Your One-Time Passcode (OTP): {otp_code}"
        msg["From"] = f"{smtp_cfg['sender_name']} <{sender_email}>"
        msg["To"] = recipient_email

        # Plain-text version
        text_content = f"""
Hello {recipient_name},

Your One-Time Passcode (OTP) for resetting your Autonomous Multi-Agent SOC Framework access password is:

{otp_code}

This code is valid for 5 minutes. If you did not request this OTP, please investigate your SOC logs immediately.

Security Operations Center Automated Dispatcher
"""

        # Rich HTML version
        html_content = f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; background-color: #0b0f19; color: #ffffff; padding: 24px; margin: 0;">
    <div style="max-width: 520px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-top: 4px solid #00d2ff; border-radius: 10px; padding: 28px; box-shadow: 0 4px 12px rgba(0,0,0,0.5);">
        <div style="text-align: center; margin-bottom: 20px;">
            <div style="font-size: 38px;">🛡️</div>
            <h2 style="color: #00d2ff; margin: 6px 0 2px 0;">AUTONOMOUS SOC SECURITY</h2>
            <p style="color: #9ca3af; font-size: 13px; margin: 0;">Multi-Agent Fraud & Cyber Threat Defense Framework</p>
        </div>
        <p style="color: #e5e7eb; font-size: 15px;">Hello <b>{recipient_name}</b>,</p>
        <p style="color: #9ca3af; font-size: 14px; line-height: 1.5;">
            You requested a password reset for your private SOC dashboard clearance. Use the verification code below to authorize your identity:
        </p>
        <div style="text-align: center; margin: 26px 0;">
            <div style="display: inline-block; background-color: #1e293b; border: 2px dashed #00d2ff; border-radius: 8px; padding: 14px 32px; font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #38bdf8;">
                {otp_code}
            </div>
        </div>
        <p style="color: #ef4444; font-size: 12px; text-align: center;">⚠️ This OTP code expires in <b>5 minutes</b>. Do not share this code with anyone.</p>
        <hr style="border: 0; border-top: 1px solid #1f2937; margin: 22px 0;">
        <p style="color: #6b7280; font-size: 11px; text-align: center; margin: 0;">
            Autonomous Multi-Agent SOC Framework &bull; Incident Command
        </p>
    </div>
</body>
</html>
"""

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        # Connect and send
        server = smtplib.SMTP(smtp_cfg["server"], smtp_cfg["port"], timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, [recipient_email], msg.as_string())
        server.quit()

        return True, f"OTP email successfully sent to {recipient_email}!"
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP Authentication Failed: Invalid Google App Password. Please generate a 16-character App Password at https://myaccount.google.com/apppasswords"
    except Exception as e:
        return False, f"Failed to send email via SMTP: {str(e)}"


def send_sms_otp(mobile_number: str, otp_code: str) -> Tuple[bool, str]:
    """
    Sends a real SMS OTP to the user's mobile number.
    Supports Fast2SMS (Indian numbers) and Twilio (Global).
    """
    sms_cfg = get_sms_config()
    clean_digits = re.sub(r"\D", "", mobile_number)

    # Fast2SMS (India)
    if sms_cfg["fast2sms_key"]:
        target_number = clean_digits[-10:]
        
        # 1. Smart OTP Route (Preferred - No DLT recharge required)
        if sms_cfg.get("fast2sms_otp_id"):
            try:
                url_smart = "https://www.fast2sms.com/dev/otp/send"
                payload_smart = {
                    "otp_id": sms_cfg["fast2sms_otp_id"],
                    "mobile": target_number,
                    "otp": otp_code,
                    "otp_length": len(otp_code),
                    "otp_expiry": 10
                }
                data_smart = json.dumps(payload_smart).encode("utf-8")
                req_smart = urllib.request.Request(url_smart, data=data_smart, method="POST")
                req_smart.add_header("authorization", sms_cfg["fast2sms_key"])
                req_smart.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req_smart, timeout=10) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    if resp_data.get("return") is True:
                        return True, f"SMS OTP delivered to +91 {target_number} via Fast2SMS Smart OTP!"
            except Exception as e:
                pass

        # 2. Bulk V2 Route (Fallback)
        try:
            url = "https://www.fast2sms.com/dev/bulkV2"
            payload_otp = {
                "variables_values": otp_code,
                "route": "otp",
                "numbers": target_number
            }
            data_otp = json.dumps(payload_otp).encode("utf-8")
            req = urllib.request.Request(url, data=data_otp, method="POST")
            req.add_header("authorization", sms_cfg["fast2sms_key"])
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req, timeout=10) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
                if resp_data.get("return") is True:
                    return True, f"SMS OTP successfully delivered to +91 {target_number} via Fast2SMS!"
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
                err_msg = err_body.get("message", "Fast2SMS Bad Request")
            except Exception:
                err_msg = str(e)
            return False, f"Fast2SMS Notice: {err_msg}"
        except Exception as e:
            return False, f"Fast2SMS request failed: {str(e)}"

    # Twilio (Global)
    if sms_cfg["twilio_sid"] and sms_cfg["twilio_token"] and sms_cfg["twilio_from"]:
        try:
            import base64
            auth_str = f"{sms_cfg['twilio_sid']}:{sms_cfg['twilio_token']}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")

            dest_number = f"+{clean_digits}" if not mobile_number.startswith("+") else mobile_number
            url = f"https://api.twilio.com/2010-04-01/Accounts/{sms_cfg['twilio_sid']}/Messages.json"
            payload = {
                "To": dest_number,
                "From": sms_cfg["twilio_from"],
                "Body": f"[SOC Security Alert] Your verification OTP code is: {otp_code}. Valid for 5 minutes."
            }
            data = urllib.parse.urlencode(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Authorization", f"Basic {b64_auth}")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

            with urllib.request.urlopen(req, timeout=8) as response:
                if response.getcode() in [200, 201]:
                    return True, f"SMS OTP successfully sent to {dest_number} via Twilio!"
                else:
                    return False, f"Twilio returned status {response.getcode()}"
        except Exception as e:
            return False, f"Twilio SMS failed: {str(e)}"

    return False, "SMS Gateway not configured. Set FAST2SMS_API_KEY (for Indian numbers) or Twilio credentials in .env to deliver real SMS."


def dispatch_real_otp(identifier: str, otp_code: str, recipient_email: str, recipient_mobile: str) -> Dict[str, Any]:
    """
    Attempts real delivery to both Gmail and Mobile number based on configured services.
    """
    email_ok, email_msg = send_email_otp(recipient_email, otp_code)
    sms_ok, sms_msg = send_sms_otp(recipient_mobile, otp_code)

    return {
        "email_sent": email_ok,
        "email_msg": email_msg,
        "sms_sent": sms_ok,
        "sms_msg": sms_msg,
        "any_sent": (email_ok or sms_ok)
    }


def save_gateway_config(
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
    fast2sms_key: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Saves and updates SMTP and SMS Gateway configuration in .env and current runtime environment.
    """
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(env_path):
        return False, ".env file not found."

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            content = f.read()

        if smtp_user is not None and smtp_user.strip():
            u = smtp_user.strip()
            os.environ["SMTP_USER"] = u
            if "SMTP_USER=" in content:
                content = re.sub(r'SMTP_USER=.*', f'SMTP_USER={u}', content)
            else:
                content += f"\nSMTP_USER={u}"

        if smtp_password is not None and smtp_password.strip():
            p = smtp_password.strip()
            os.environ["SMTP_PASSWORD"] = p
            if "SMTP_PASSWORD=" in content:
                content = re.sub(r'SMTP_PASSWORD=.*', f'SMTP_PASSWORD={p}', content)
            else:
                content += f"\nSMTP_PASSWORD={p}"

        if fast2sms_key is not None and fast2sms_key.strip():
            k = fast2sms_key.strip()
            os.environ["FAST2SMS_API_KEY"] = k
            if "FAST2SMS_API_KEY=" in content:
                content = re.sub(r'FAST2SMS_API_KEY=.*', f'FAST2SMS_API_KEY={k}', content)
            else:
                content += f"\nFAST2SMS_API_KEY={k}"

        with open(env_path, "w", encoding="utf-8") as f:
            f.write(content)

        return True, "Gateway settings saved successfully! Real OTPs will now be delivered."
    except Exception as e:
        return False, f"Failed to save gateway settings: {e}"
