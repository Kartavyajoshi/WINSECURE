"""
WinSecure UI Screenshot Capture Script
Captures high-resolution interface views of the WinSecure platform and audit reports.
"""
import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def capture_all():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    out_dir = os.path.join(base_dir, "docs", "screenshots")
    os.makedirs(out_dir, exist_ok=True)

    report_path = "file:///" + os.path.join(base_dir, "reports", "index.html").replace("\\", "/")
    site_path = "file:///" + os.path.join(base_dir, "index.html").replace("\\", "/")

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--force-device-scale-factor=1.25")
    options.add_argument("--window-size=1600,1050")

    driver = webdriver.Chrome(options=options)
    try:
        # 1. Assessment Report Dashboard
        print(f"[1/5] Capturing Assessment Report Dashboard from {report_path}...")
        driver.get(report_path)
        time.sleep(1)
        p1 = os.path.join(out_dir, "01_assessment_dashboard.png")
        driver.save_screenshot(p1)
        print(f" -> Saved {p1} ({os.path.getsize(p1):,} bytes)")

        # 2. Findings & PowerShell Remediation
        print("[2/5] Capturing Findings & PowerShell Remediation...")
        driver.execute_script("window.scrollTo(0, 850);")
        time.sleep(0.5)
        p2 = os.path.join(out_dir, "02_findings_remediation.png")
        driver.save_screenshot(p2)
        print(f" -> Saved {p2} ({os.path.getsize(p2):,} bytes)")

        # 3. Platform Website Hero & Terminal
        print(f"[3/5] Capturing Platform Website Hero from {site_path}...")
        driver.get(site_path)
        time.sleep(1)
        p3 = os.path.join(out_dir, "03_platform_landing.png")
        driver.save_screenshot(p3)
        print(f" -> Saved {p3} ({os.path.getsize(p3):,} bytes)")

        # 4. 36 Security Modules Grid
        print("[4/5] Capturing 36 Security Modules Grid...")
        elem = driver.find_element("id", "modules")
        driver.execute_script("arguments[0].scrollIntoView(true);", elem)
        time.sleep(0.5)
        p4 = os.path.join(out_dir, "04_modules_catalog.png")
        driver.save_screenshot(p4)
        print(f" -> Saved {p4} ({os.path.getsize(p4):,} bytes)")

        # 5. Desktop GUI Cockpit Overview
        print("[5/5] Capturing Desktop GUI Cockpit Section...")
        elem = driver.find_element("id", "gui-studio")
        driver.execute_script("arguments[0].scrollIntoView(true);", elem)
        time.sleep(0.5)
        p5 = os.path.join(out_dir, "05_desktop_gui_cockpit.png")
        driver.save_screenshot(p5)
        print(f" -> Saved {p5} ({os.path.getsize(p5):,} bytes)")

        print("\nAll 5 UI screenshots successfully captured!")
    finally:
        driver.quit()

if __name__ == "__main__":
    capture_all()
