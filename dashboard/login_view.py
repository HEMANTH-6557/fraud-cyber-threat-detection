"""
Professional Enterprise Login Portal & Session Management View.
Autonomous Multi-Agent Fraud & Cyber Threat Detection System.
"""

import streamlit as st
import time
import random
from typing import Optional
from core.auth import (
    authenticate_user,
    update_credentials,
    reset_password,
    load_credentials,
    get_masked_profile,
    normalize_email
)
from core.otp_service import send_email_otp


def is_authenticated() -> bool:
    """Checks whether the current session is authenticated."""
    return st.session_state.get("authenticated", False) is True


def logout():
    """Logs the user out and clears sensitive session state."""
    st.session_state["authenticated"] = False
    st.session_state.pop("user_info", None)
    st.session_state.pop("investigation_state", None)
    st.session_state.pop("selected_alert_id", None)
    st.session_state.pop("current_investigation_alert", None)
    st.session_state.pop("remember_me", None)
    st.rerun()


def render_login_page():
    """
    Renders the modern enterprise split-panel login screen.
    Left Panel: Project Identity & Autonomous Multi-Agent Architecture.
    Right Panel: Clean, High-Contrast Authentication Card.
    """
    profile = get_masked_profile()
    creds = load_credentials()

    # Enterprise Styling
    st.markdown("""
<style>
/* Overall Page Background & Typography */
.stApp {
    background: linear-gradient(135deg, #070c14 0%, #0d1522 50%, #0a111c 100%);
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
}

/* Hide Streamlit Default Header for Clean Layout */
header[data-testid="stHeader"] {
    background: transparent;
}

/* Left Brand Panel */
.brand-panel-card {
    background: linear-gradient(165deg, #071e22 0%, #0c2b2e 45%, #09171f 100%);
    padding: 44px 38px;
    height: 100%;
    min-height: 520px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    border-radius: 16px;
    border: 1px solid rgba(45, 212, 191, 0.2);
    box-shadow: 0 20px 45px -10px rgba(0, 0, 0, 0.7);
}

.brand-header-badge {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 32px;
}

.brand-logo-shield {
    background: rgba(45, 212, 191, 0.15);
    border: 1.5px solid #2dd4bf;
    width: 42px;
    height: 42px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
}

.brand-badge-title {
    color: #ffffff;
    font-weight: 700;
    font-size: 1.15em;
    letter-spacing: -0.2px;
}

.brand-badge-sub {
    color: #2dd4bf;
    font-size: 0.72em;
    font-weight: 700;
    letter-spacing: 1.2px;
    text-transform: uppercase;
}

.project-title-box {
    border-left: 4px solid #2dd4bf;
    padding-left: 22px;
    margin: 28px 0 24px 0;
}

.project-kicker {
    color: #2dd4bf;
    font-size: 0.82em;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 12px;
}

.project-main-heading {
    color: #ffffff;
    font-size: 2.1em;
    font-weight: 800;
    line-height: 1.25;
    margin: 0;
    letter-spacing: -0.5px;
}

.project-tagline {
    color: #94a3b8;
    font-size: 0.95em;
    line-height: 1.6;
    margin: 20px 0 0 0;
}

.brand-panel-footer {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid rgba(255, 255, 255, 0.08);
    font-size: 0.82em;
    color: #64748b;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

/* Right Auth Panel */
.auth-panel-container {
    padding: 10px 4px;
}

.auth-header-title {
    color: #ffffff;
    font-weight: 800;
    font-size: 1.9em;
    margin: 0 0 6px 0;
    letter-spacing: -0.5px;
}

.auth-header-desc {
    color: #94a3b8;
    font-size: 0.92em;
    margin: 0 0 24px 0;
}

/* Input Customizations */
div[data-testid="stTextInput"] label p {
    color: #e2e8f0 !important;
    font-weight: 600 !important;
    font-size: 0.9em !important;
}

/* Primary Button */
div.stButton > button[kind="primary"] {
    background-color: #0d9488 !important;
    border-color: #0d9488 !important;
    color: #ffffff !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
    padding: 0.6rem 1rem !important;
    font-size: 1.0em !important;
    margin-top: 10px !important;
    transition: all 0.2s ease !important;
}

div.stButton > button[kind="primary"]:hover {
    background-color: #0f766e !important;
    border-color: #0f766e !important;
    box-shadow: 0 4px 15px rgba(13, 148, 136, 0.4) !important;
}

.security-footer-note {
    text-align: center;
    margin-top: 24px;
    font-size: 0.82em;
    color: #64748b;
}
</style>
""", unsafe_allow_html=True)

    # Responsive Split Columns
    left_col, right_col = st.columns([1.18, 1.0], gap="large")

    # ==========================================================================
    # LEFT PANEL: Project Name & Identity
    # ==========================================================================
    with left_col:
        st.markdown(
            '<div style="'
            'background: linear-gradient(165deg, #071e22 0%, #0c2b2e 45%, #09171f 100%); '
            'padding: 48px 40px; '
            'height: 100%; '
            'min-height: 520px; '
            'display: flex; '
            'flex-direction: column; '
            'justify-content: center; '
            'border-radius: 18px; '
            'border: 1.5px solid rgba(45, 212, 191, 0.3); '
            'box-shadow: 0 20px 45px -10px rgba(0, 0, 0, 0.7);">'
            '<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 24px;">'
            '<span style="font-size: 32px; filter: drop-shadow(0 2px 8px rgba(45,212,191,0.4));">🛡️</span>'
            '<span style="color: #2dd4bf; font-size: 0.85em; font-weight: 800; letter-spacing: 2px; text-transform: uppercase;">Cybersecurity Operations Center</span>'
            '</div>'
            '<div style="border-left: 4px solid #2dd4bf; padding-left: 22px; margin: 16px 0 24px 0;">'
            '<h1 style="'
            'color: #ffffff; '
            'font-size: 2.3em; '
            'font-weight: 800; '
            'line-height: 1.35; '
            'margin: 0; '
            'letter-spacing: -0.5px; '
            'font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, \'Inter\', sans-serif;">'
            'An Autonomous Multi-Agent Framework<br>'
            'for Fraud and Cyber Threat Detection<br>'
            '<span style="background: linear-gradient(90deg, #2dd4bf, #38bdf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Using Large Language Models</span>'
            '</h1>'
            '</div>'
            '<p style="color: #94a3b8; font-size: 0.98em; line-height: 1.6; margin: 20px 0 0 0;">'
            'Two-Tier Collaborative AI Architecture for Real-Time Threat Ingestion, Fast ML Screening, and Autonomous Multi-Agent Forensic Investigation.'
            '</p>'
            '</div>',
            unsafe_allow_html=True
        )

    # ==========================================================================
    # RIGHT PANEL: Enterprise Authentication Card
    # ==========================================================================
    with right_col:
        st.markdown(
            '<div class="auth-panel-container">'
            '<h2 class="auth-header-title">Welcome Back</h2>'
            '<p class="auth-header-desc">Sign in to your security operations workspace.</p>'
            '</div>',
            unsafe_allow_html=True
        )

        # Form Inputs
        email_val = st.text_input(
            "Email Address",
            placeholder="name@company.com",
            help="Enter your registered operator email (e.g. hemanthhemu6557@gmail.com) or username.",
            key="login_user_input"
        )

        pwd_val = st.text_input(
            "Password",
            type="password",
            placeholder="••••••••",
            help="Enter your private access password.",
            key="login_password_input"
        )

        remember_me = st.checkbox("Keep me signed in", value=True, key="chk_keep_signed_in")

        sign_in_clicked = st.button(
            "Sign In to Dashboard",
            type="primary",
            use_container_width=True,
            key="btn_sign_in_dashboard"
        )

        if sign_in_clicked:
            if not email_val or not email_val.strip():
                st.error("Please enter your registered email address or username.")
            elif not pwd_val:
                st.error("Please enter your access password.")
            else:
                with st.spinner("Verifying credentials..."):
                    success, msg, user_data = authenticate_user(
                        identifier=email_val.strip(),
                        password=pwd_val,
                        auth_type="email"
                    )
                    if success:
                        st.session_state["authenticated"] = True
                        st.session_state["user_info"] = user_data
                        st.session_state["remember_me"] = remember_me
                        st.success(f"✅ Access Granted! Welcome back, {user_data.get('name', 'Operator')}.")
                        time.sleep(0.3)
                        st.rerun()
                    else:
                        st.error(f"❌ {msg}")

        # Dedicated Forgot Password / Recovery Flow
        with st.expander("🔑 Forgot Password?"):
            st.markdown("<small style='color: #94a3b8;'>Enter your registered email address to receive a 6-digit verification code directly to your Gmail inbox.</small>", unsafe_allow_html=True)

            fp_email = st.text_input("Enter Registered Email Address", placeholder="hemanthhemu6557@gmail.com", key="fp_email_field")
            if st.button("📲 Send Verification Code to Email", use_container_width=True, key="btn_fp_send_code"):
                if not fp_email.strip():
                    st.warning("Please enter your registered email address above.")
                else:
                    creds_check = load_credentials()
                    clean_email = fp_email.strip()
                    if normalize_email(clean_email) == creds_check["email"]:
                        otp_code = str(random.randint(100000, 999999))
                        st.session_state["active_reset_otp"] = otp_code
                        st.session_state["active_reset_email"] = clean_email

                        ok_mail, mail_msg = send_email_otp(creds_check["email"], otp_code)
                        st.session_state["otp_email_sent"] = ok_mail
                        st.session_state["otp_email_msg"] = mail_msg
                        print(f"\n[SECURITY AUDIT] Reset Code for {clean_email}: {otp_code}\n")
                        st.success("Verification code dispatched to your registered email.")
                    else:
                        st.error("Account not recognized. Please provide the authorized operator email.")

            with st.form("pwd_reset_submission_form"):
                otp_code_in = st.text_input("6-Digit Verification Code", placeholder="e.g. 123456", max_chars=6)
                new_pw = st.text_input("New Password", type="password", placeholder="Enter at least 6 characters")
                confirm_pw = st.text_input("Confirm New Password", type="password", placeholder="Re-enter password")

                if st.form_submit_button("Reset Password & Update Credentials", type="primary", use_container_width=True):
                    active_otp = st.session_state.get("active_reset_otp")
                    if not fp_email.strip():
                        st.error("Please enter your registered email address.")
                    elif not otp_code_in.strip():
                        st.error("Please enter the verification code received.")
                    elif not active_otp or otp_code_in.strip() != active_otp:
                        st.error("Invalid or expired verification code.")
                    elif not new_pw or len(new_pw) < 6:
                        st.error("Password must be at least 6 characters long.")
                    elif new_pw != confirm_pw:
                        st.error("Passwords do not match.")
                    else:
                        ok, msg = reset_password(fp_email, new_pw)
                        if ok:
                            st.session_state.pop("active_reset_otp", None)
                            st.session_state.pop("active_reset_email", None)
                            st.success("✅ Password successfully reset! You can now sign in with your new credentials.")
                            time.sleep(1.0)
                            st.rerun()
                        else:
                            st.error(msg)

        # Restrained Security Notice
        st.markdown("""
<div class="security-footer-note">
    🔒 Protected access to your AI security investigation workspace.<br>
    <span style="font-size: 0.85em; color: #475569;">Authorized Personnel Only • Audit Log Active</span>
</div>
""", unsafe_allow_html=True)


def render_auth_sidebar():
    """Renders authenticated operator status and controls in the sidebar."""
    user = st.session_state.get("user_info", {})
    user_name = user.get("name", "Hemanth Gowda T")
    auth_method = user.get("auth_method", "Enterprise Workspace")

    st.sidebar.markdown(f"""
<div style="background-color: #0f172a; border: 1px solid #1e293b; border-left: 4px solid #2dd4bf; border-radius: 8px; padding: 12px; margin-bottom: 14px;">
    <div style="display: flex; align-items: center; justify-content: space-between;">
        <b style="color: #2dd4bf; font-size: 0.85em;">🟢 ACTIVE SESSION</b>
    </div>
    <div style="color: #f8fafc; font-weight: 600; font-size: 1.05em; margin-top: 4px;">{user_name}</div>
    <div style="color: #94a3b8; font-size: 0.8em;">SOC Lead Operator | {auth_method}</div>
</div>
""", unsafe_allow_html=True)

    if st.sidebar.button("🚪 Logout & Lock SOC", use_container_width=True, type="secondary"):
        logout()
