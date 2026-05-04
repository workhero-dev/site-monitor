import os
import json
import urllib.request
import urllib.error
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# --- Config from environment variables ---
SAFE_BROWSING_API_KEY = os.environ["SAFE_BROWSING_API_KEY"]
GMAIL_ADDRESS = os.environ["GMAIL_ADDRESS"]
GMAIL_APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]
ALERT_EMAIL = os.environ["ALERT_EMAIL"]

# --- Load sites ---
with open("sites.txt") as f:
    sites = [line.strip() for line in f if line.strip()]

print(f"Checking {len(sites)} sites at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

# --- Check Google Safe Browsing ---
def check_safe_browsing(urls):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "site-monitor", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(api_url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            flagged = {}
            for match in result.get("matches", []):
                url = match["threat"]["url"]
                threat = match["threatType"]
                flagged[url] = flagged.get(url, [])
                flagged[url].append(threat)
            return flagged
    except Exception as e:
        print(f"Safe Browsing API error: {e}")
        return {}

# --- Check if site is reachable ---
def check_uptime(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 SiteMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, None
    except urllib.error.HTTPError as e:
        return e.code, str(e)
    except Exception as e:
        return None, str(e)

# --- Send email alert ---
def send_email(subject, body):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = ALERT_EMAIL
    msg.attach(MIMEText(body, "html"))
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_ADDRESS, ALERT_EMAIL, msg.as_string())
    print("Alert email sent.")

# --- Run checks ---
flagged_sites = check_safe_browsing(sites)
down_sites = {}
for site in sites:
    status, error = check_uptime(site)
    if status is None or status >= 400:
        down_sites[site] = f"Status: {status} — {error}"

# --- Build report ---
issues_found = len(flagged_sites) + len(down_sites)

if issues_found > 0:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    rows = ""

    for url, threats in flagged_sites.items():
        threat_str = ", ".join(threats)
        rows += f"""
        <tr style='background:#fff0f0'>
            <td style='padding:8px;border:1px solid #ddd'>{url}</td>
            <td style='padding:8px;border:1px solid #ddd;color:red'><b>🚨 MALWARE / BLACKLISTED</b></td>
            <td style='padding:8px;border:1px solid #ddd'>{threat_str}</td>
        </tr>"""

    for url, error in down_sites.items():
        if url not in flagged_sites:
            rows += f"""
        <tr style='background:#fffbe6'>
            <td style='padding:8px;border:1px solid #ddd'>{url}</td>
            <td style='padding:8px;border:1px solid #ddd;color:orange'><b>⚠️ DOWN / UNREACHABLE</b></td>
            <td style='padding:8px;border:1px solid #ddd'>{error}</td>
        </tr>"""

    body = f"""
    <html><body>
    <h2 style='color:#cc0000'>⚠️ Site Monitor Alert — {now}</h2>
    <p>{issues_found} issue(s) detected across your monitored sites:</p>
    <table style='border-collapse:collapse;width:100%;font-family:Arial,sans-serif;font-size:14px'>
        <tr style='background:#f2f2f2'>
            <th style='padding:8px;border:1px solid #ddd;text-align:left'>URL</th>
            <th style='padding:8px;border:1px solid #ddd;text-align:left'>Status</th>
            <th style='padding:8px;border:1px solid #ddd;text-align:left'>Details</th>
        </tr>
        {rows}
    </table>
    <br><p style='color:#888;font-size:12px'>This alert was sent automatically by your GitHub Actions site monitor.</p>
    </body></html>
    """
    send_email(f"🚨 Site Monitor Alert — {issues_found} Issue(s) Found", body)
else:
    print("All sites clean and reachable. No alert sent.")
