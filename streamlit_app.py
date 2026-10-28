"""
Main Entrypoint for Streamlit Community Cloud & Cloud Deployments.
Redirects execution into the autonomous multi-agent SOC dashboard.
"""
import sys
import os
import runpy

# Ensure root directory is on sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Dynamically execute dashboard/app.py on each run/rerun
app_path = os.path.join(ROOT_DIR, "dashboard", "app.py")
runpy.run_path(app_path, run_name="__main__")
