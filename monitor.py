import os
import json
import urllib.request
import urllib.error
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import time

# --- Config from environment variables ---
SAFE_BROWSING_API_KEY = os.environ["SAFE_BROWSING_API_KEY"]
GMAIL_ADDRESS = os.environ["GMAIL_ADDRESS"]
GMAIL_APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]
ALERT_EMAIL = os.environ["ALERT_EMAIL"]
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]

# --- Load sites ---
with open("sites.txt") as f:
    sites = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

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

# --- Check if site is reachable and grab content ---
def check_uptime(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 SiteMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_html = resp.read().decode("utf-8", errors="ignore")
            return resp.status, None, raw_html
    except urllib.error.HTTPError as e:
        return e.code, str(e), ""
    except Exception as e:
        return None, str(e), ""

# --- Strip HTML tags to get plain text ---
def strip_html(html):
    import re
    html = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<[^>]+>', ' ', html)
    html = re.sub(r'\s+', ' ', html).strip()
    return html[:3000]

# --- Analyze page content with Claude AI ---
def analyze_with_claude(url, page_text):
    if not page_text or len(page_text.strip()) < 50:
        return True, "Page appears empty or returned no content"

    prompt = f"""You are a website security monitor. Analyze the following webpage content from: {url}

Your job is to detect if this website has been hacked, compromised, or is showing abnormal content.

Look for these red flags:
- Malware or security warning messages (e.g. "This site may harm your computer")
- Spam content: pharmacy links, casino, adult content, cheap pills, fake goods
- Defacement messages from hackers
- Content in a completely wrong language for the site type
- Redirects to suspicious domains mentioned in the text
- Error messages indicating server or database problems
- Blank or nearly empty pages that should have content
- Suspicious injected links or hidden text

Page content:
{page_text}

Respond in this exact format:
STATUS: NORMAL or SUSPICIOUS
REASON: (one sentence explaining your decision)

Be conservative - only flag as SUSPICIOUS if there are clear signs of a problem."""

    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 150,
        "messages": [{"role": "user", "content": prompt}]
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            response_text = result["content"][0]["text"].strip()

            if "STATUS: SUSPICIOUS" in response_text:
                reason = "Unknown issue detected"
                for line in response_text.split("\n"):
                    if line.startswith("REASON:"):
                        reason = line.replace("REASON:", "").strip()
                return True, reason
            else:
                reason = "Page looks normal"
                for line in response_text.split("\n"):
                    if line.startswith("REASON:"):
                        reason = line.replace("REASON:", "").strip()
                print(f"  OK {url} - Claude: {reason}")
                return False, reason

    except Exception as e:
        print(f"  Claude API error for {url}: {e}")
        return False, f"Claude check skipped: {e}"

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
ai_flagged_sites = {}

for site in sites:
    print(f"Checking: {site}")
    status, error, html_content = check_uptime(site)

    # Layer 1: Down check
    if status is None or status >= 400:
        down_sites[site] = f"Status: {status} - {error}"
        print(f"  DOWN: {site} - {error}")
        continue

    # Layer 3: Claude AI content analysis (only if site is up and not already blacklisted)
    if site not in flagged_sites:
        page_text = strip_html(html_content)
        is_suspicious, reason = analyze_with_claude(site, page_text)
        time.sleep(10)
        if is_suspicious:
            ai_flagged_sites[site] = reason
            print(f"  AI FLAGGED: {site} - {reason}")

# --- Build report ---
issues_found = len(flagged_sites) + len(down_sites) + len(ai_flagged_sites)

if issues_found > 0:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    rows = ""

    for url, threats in flagged_sites.items():
        threat_str = ", ".join(threats)
        rows += f"""
        <tr style='background:#fff0f0'>
            <td style='padding:8px;border:1px solid #ddd'>{url}</td>
            <td style='padding:8px;border:1px solid #ddd;color:red'><b>MALWARE / BLACKLISTED</b></td>
            <td style='padding:8px;border:1px solid #ddd'>{threat_str}</td>
        </tr>"""

    for url, error in down_sites.items():
        if url not in flagged_sites:
            rows += f"""
        <tr style='background:#fffbe6'>
            <td style='padding:8px;border:1px solid #ddd'>{url}</td>
            <td style='padding:8px;border:1px solid #ddd;color:orange'><b>DOWN / UNREACHABLE</b></td>
            <td style='padding:8px;border:1px solid #ddd'>{error}</td>
        </tr>"""

    for url, reason in ai_flagged_sites.items():
        rows += f"""
        <tr style='background:#f0f4ff'>
            <td style='padding:8px;border:1px solid #ddd'>{url}</td>
            <td style='padding:8px;border:1px solid #ddd;color:#3a3adb'><b>AI FLAGGED - SUSPICIOUS CONTENT</b></td>
            <td style='padding:8px;border:1px solid #ddd'>{reason}</td>
        </tr>"""

    body = f"""
    <html><body>
    <h2 style='color:#cc0000'>Site Monitor Alert - {now}</h2>
    <p>{issues_found} issue(s) detected across your monitored sites:</p>
    <table style='border-collapse:collapse;width:100%;font-family:Arial,sans-serif;font-size:14px'>
        <tr style='background:#f2f2f2'>
            <th style='padding:8px;border:1px solid #ddd;text-align:left'>URL</th>
            <th style='padding:8px;border:1px solid #ddd;text-align:left'>Status</th>
            <th style='padding:8px;border:1px solid #ddd;text-align:left'>Details</th>
        </tr>
        {rows}
    </table>
    <br>
    <p style='font-size:12px;color:#888'>
        Checks: HTTP Uptime | Google Safe Browsing | Claude AI Content Analysis<br>
        Sent automatically by your GitHub Actions site monitor.
    </p>
    </body></html>
    """
    send_email(f"Site Monitor Alert - {issues_found} Issue(s) Found", body)
else:
    print("All sites clean and reachable. No alert sent.")
