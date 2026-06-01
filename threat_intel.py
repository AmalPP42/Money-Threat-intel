"""
Automated Threat Intelligence Feed
Zero-cost edition: uses Groq free API (Llama 3) instead of OpenAI
"""

from dotenv import load_dotenv
load_dotenv()

import feedparser
import requests
import os
import sqlite3
import json
import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
KEYWORDS = [
    "zero-day", "0-day", "ransomware", "breach", "exploit", "vulnerability",
    "malware", "phishing", "backdoor", "cve-", "remote code execution", "rce",
    "data leak", "supply chain", "apt", "botnet", "trojan", "rootkit",
    "privilege escalation", "lateral movement", "credential", "exfiltration",
]

# MITRE ATT&CK tactic keywords for auto-tagging
MITRE_TACTICS = {
    "Initial Access":       ["phishing", "exploit", "supply chain", "credential"],
    "Execution":            ["remote code execution", "rce", "malware", "trojan"],
    "Persistence":          ["backdoor", "rootkit", "registry"],
    "Privilege Escalation": ["privilege escalation", "elevation"],
    "Defense Evasion":      ["obfuscat", "rootkit", "defense evasion"],
    "Credential Access":    ["credential", "password", "hash", "kerberos"],
    "Discovery":            ["reconnaissance", "scanning", "enumeration"],
    "Lateral Movement":     ["lateral movement", "pass-the-hash", "smb"],
    "Collection":           ["exfiltration", "data theft", "keylogger"],
    "Impact":               ["ransomware", "wiper", "ddos", "denial of service"],
}

# Free RSS feeds — no API key needed
RSS_FEEDS = [
    # Tier 1: High signal
    ("The Hacker News",    "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer",   "https://www.bleepingcomputer.com/feed/"),
    ("Dark Reading",       "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security",  "https://krebsonsecurity.com/feed/"),
    ("Schneier on Security","https://www.schneier.com/feed/atom/"),
    # Tier 2: Official / CVE sources
    ("CISA Alerts",        "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("SecurityWeek",       "https://feeds.feedburner.com/securityweek"),
    ("Naked Security",     "https://nakedsecurity.sophos.com/feed/"),
    ("Threatpost",         "https://threatpost.com/feed/"),
]

DISCORD_WEBHOOK  = os.getenv("DISCORD_WEBHOOK")
SLACK_WEBHOOK    = os.getenv("SLACK_WEBHOOK")        # optional
EMAIL_TO         = os.getenv("EMAIL_TO")             # optional (uses Gmail free tier)
GROQ_API_KEY     = os.getenv("GROQ_API_KEY")         # free at console.groq.com
DB_PATH          = os.getenv("DB_PATH", "seen_articles.db")

ARTICLES_PER_FEED  = 8
MAX_ARTICLES_REPORT = 15  # cap to stay under token limits


# ── Database (deduplication) ──────────────────────────────────────────────────
def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS seen (
            url TEXT PRIMARY KEY,
            title TEXT,
            seen_at TEXT
        )
    """)
    conn.commit()
    return conn


def is_seen(conn: sqlite3.Connection, url: str) -> bool:
    row = conn.execute("SELECT 1 FROM seen WHERE url = ?", (url,)).fetchone()
    return row is not None


def mark_seen(conn: sqlite3.Connection, url: str, title: str):
    conn.execute(
        "INSERT OR IGNORE INTO seen (url, title, seen_at) VALUES (?, ?, ?)",
        (url, title, datetime.now(timezone.utc).replace(tzinfo=None).isoformat()),
    )
    conn.commit()


def purge_old(conn: sqlite3.Connection, days: int = 30):
    """Remove entries older than `days` to keep the DB lean."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).replace(tzinfo=None).isoformat()
    conn.execute("DELETE FROM seen WHERE seen_at < ?", (cutoff,))
    conn.commit()


# ── Fetching ──────────────────────────────────────────────────────────────────
def fetch_articles(conn: sqlite3.Connection) -> list[dict]:
    articles = []
    for source_name, url in RSS_FEEDS:
        try:
            parsed = feedparser.parse(url)
            count = 0
            for entry in parsed.entries[:ARTICLES_PER_FEED]:
                link = entry.get("link", "")
                if not link or is_seen(conn, link):
                    continue
                articles.append({
                    "source":  source_name,
                    "title":   entry.get("title", "Untitled"),
                    "link":    link,
                    "summary": entry.get("summary", entry.get("description", ""))[:500],
                    "published": entry.get("published", ""),
                })
                count += 1
            log.info("✓ %s → %d new articles", source_name, count)
        except Exception as e:
            log.warning("✗ Failed to fetch %s: %s", source_name, e)
    log.info("Total new articles fetched: %d", len(articles))
    return articles


# ── Filtering ─────────────────────────────────────────────────────────────────
def filter_articles(articles: list[dict]) -> list[dict]:
    filtered = []
    for art in articles:
        text = (art["title"] + " " + art["summary"]).lower()
        matched = [kw for kw in KEYWORDS if kw in text]
        if matched:
            art["matched_keywords"] = matched
            art["mitre_tactics"] = detect_mitre(text)
            filtered.append(art)
    log.info("Threat-related articles after filtering: %d", len(filtered))
    return filtered[:MAX_ARTICLES_REPORT]


def detect_mitre(text: str) -> list[str]:
    """Map article text to MITRE ATT&CK tactics."""
    tactics = []
    for tactic, signals in MITRE_TACTICS.items():
        if any(s in text for s in signals):
            tactics.append(tactic)
    return tactics


# ── Severity Scoring (heuristic, zero-cost) ────────────────────────────────
SEVERITY_SIGNALS = {
    "critical": ["zero-day", "0-day", "actively exploited", "in the wild", "critical",
                 "remote code execution", "rce", "worm", "ransomware", "apt", "supply chain"],
    "high":     ["exploit", "breach", "backdoor", "privilege escalation", "exfiltration",
                 "data leak", "botnet", "malware"],
    "medium":   ["vulnerability", "phishing", "credential", "patch", "advisory",
                 "disclosure", "cve-"],
}

def score_severity(article: dict) -> str:
    text = (article["title"] + " " + article["summary"]).lower()
    for level in ["critical", "high", "medium"]:
        if any(sig in text for sig in SEVERITY_SIGNALS[level]):
            return level
    return "low"


# ── AI Summarisation (Groq free tier — Llama 3 70B) ─────────────────────────
def summarize_with_groq(articles: list[dict]) -> Optional[str]:
    """Use Groq's free API. Sign up at console.groq.com — no credit card needed."""
    if not GROQ_API_KEY:
        return None

    text_block = "\n\n".join([
        f"[{a['source']}] {a['title']}\n{a['summary'][:300]}"
        for a in articles
    ])

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama3-70b-8192",   # free on Groq
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a senior SOC analyst writing a concise daily threat briefing. "
                            "In 120 words: identify the 2-3 most urgent threats, name affected systems/vendors "
                            "where known, and state recommended defensive actions. Be direct and technical. "
                            "No fluff, no disclaimers."
                        ),
                    },
                    {"role": "user", "content": text_block},
                ],
                "max_tokens": 300,
                "temperature": 0.3,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        log.warning("Groq API error: %s", e)
        return None


def summarize_fallback(articles: list[dict]) -> str:
    """Pure-local fallback — no API at all."""
    critical = [a for a in articles if score_severity(a) == "critical"]
    high     = [a for a in articles if score_severity(a) == "high"]
    lines = [f"📊 {len(articles)} threats detected today."]
    if critical:
        lines.append(f"🔴 CRITICAL ({len(critical)}): " + " | ".join(a["title"] for a in critical[:3]))
    if high:
        lines.append(f"🟠 HIGH ({len(high)}): " + " | ".join(a["title"] for a in high[:3]))
    lines.append("⚠️ Review all articles below and patch accordingly.")
    return "\n".join(lines)


def summarize(articles: list[dict]) -> str:
    if not articles:
        return "✅ No major cybersecurity threats detected today."
    ai_summary = summarize_with_groq(articles)
    if ai_summary:
        log.info("AI summary generated via Groq.")
        return ai_summary
    log.info("Using fallback summary (no API key or Groq unavailable).")
    return summarize_fallback(articles)


# ── Discord Output ────────────────────────────────────────────────────────────
SEVERITY_COLORS = {"critical": 0xFF0000, "high": 0xFF8C00, "medium": 0xFFD700, "low": 0x00BFFF}
SEVERITY_EMOJI  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
NEWSLETTER_DIR = os.getenv("NEWSLETTER_DIR", "docs/newsletter")

def send_to_discord(summary: str, articles: list[dict]):
    if not DISCORD_WEBHOOK:
        log.info("No DISCORD_WEBHOOK set — skipping Discord.")
        return

    date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")

    # Count by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in articles:
        counts[score_severity(a)] += 1

    severity_bar = "  ".join(
        f"{SEVERITY_EMOJI[s]} {s.upper()}: {n}"
        for s, n in counts.items() if n > 0
    )

    # Main embed
    embeds = [{
        "title": f"🛡️ Daily Threat Intel — {date_str}",
        "description": summary,
        "color": 0x2F3136,
        "fields": [
            {"name": "Severity Breakdown", "value": severity_bar or "None", "inline": False},
            {"name": "Total Threats", "value": str(len(articles)), "inline": True},
            {"name": "Sources", "value": str(len({a["source"] for a in articles})), "inline": True},
        ],
        "footer": {"text": "Automated Threat Intel Feed • github.com/ara-5/Automated-threat-intel-feed"},
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }]

    # Per-article embeds (top 8, sorted by severity)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_articles = sorted(articles, key=lambda a: severity_order[score_severity(a)])

    for art in sorted_articles[:8]:
        sev = score_severity(art)
        tactics = ", ".join(art.get("mitre_tactics", [])) or "—"
        keywords = ", ".join(art.get("matched_keywords", [])[:5]) or "—"
        embeds.append({
            "title": f"{SEVERITY_EMOJI[sev]} {art['title'][:200]}",
            "url": art["link"],
            "color": SEVERITY_COLORS[sev],
            "fields": [
                {"name": "Source",         "value": art["source"],  "inline": True},
                {"name": "Severity",       "value": sev.upper(),    "inline": True},
                {"name": "MITRE Tactics",  "value": tactics,        "inline": False},
                {"name": "Keywords",       "value": keywords,       "inline": False},
            ],
        })

    try:
        resp = requests.post(
            DISCORD_WEBHOOK,
            json={"embeds": embeds[:10]},   # Discord max 10 embeds per message
            timeout=15,
        )
        resp.raise_for_status()
        log.info("✓ Sent to Discord (%d embeds)", len(embeds[:10]))
    except Exception as e:
        log.error("✗ Discord error: %s", e)


# ── Slack Output (optional) ───────────────────────────────────────────────────
def send_to_slack(summary: str, articles: list[dict]):
    if not SLACK_WEBHOOK:
        return

    date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")
    lines = [f"*🛡️ Daily Threat Intel — {date_str}*\n", summary, ""]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for art in sorted(articles, key=lambda a: severity_order[score_severity(a)])[:8]:
        sev  = score_severity(art)
        emoji = SEVERITY_EMOJI[sev]
        lines.append(f"{emoji} *<{art['link']}|{art['title']}>*  `{art['source']}` · {sev.upper()}")

    try:
        resp = requests.post(
            SLACK_WEBHOOK,
            json={"text": "\n".join(lines)},
            timeout=15,
        )
        resp.raise_for_status()
        log.info("✓ Sent to Slack")
    except Exception as e:
        log.error("✗ Slack error: %s", e)


# ── JSON archive (saved to repo via Actions) ──────────────────────────────────
def save_json_report(summary: str, articles: list[dict]):
    report = {
        "date":     datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "summary":  summary,
        "articles": [
            {
                "title":        a["title"],
                "link":         a["link"],
                "source":       a["source"],
                "severity":     score_severity(a),
                "mitre_tactics": a.get("mitre_tactics", []),
                "keywords":     a.get("matched_keywords", []),
            }
            for a in articles
        ],
    }
    path = os.path.join("docs", f"report_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json")
    os.makedirs("docs", exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    log.info("✓ JSON report saved → %s", path)

    # Also overwrite latest.json for easy API access
    with open(os.path.join("docs", "latest.json"), "w") as f:
        json.dump(report, f, indent=2)


# ── Newsletter Output ──────────────────────────────────────────────────────────
def generate_newsletter(summary: str, articles: list[dict]) -> tuple[str, str]:
    """Generate markdown (Substack-ready) and HTML newsletter versions.

    Returns (markdown, html) strings saved to docs/newsletter/.
    """
    date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")
    file_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    os.makedirs(NEWSLETTER_DIR, exist_ok=True)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_articles = sorted(articles, key=lambda a: severity_order[score_severity(a)])

    # ── Markdown (Substack copy-paste) ────────────────────────────────────────
    md_lines = [
        f"# 🛡️ Daily Threat Intel — {date_str}",
        "",
        "> **Automated daily briefing** covering the most critical cybersecurity ",
        "> threats from 9 leading security news sources.",
        "",
        "---",
        "",
        "## 📊 Analyst Briefing",
        "",
    ]
    for line in summary.split("\n"):
        md_lines.append(line)
    md_lines.append("")
    md_lines.append("---")
    md_lines.append("")
    md_lines.append("## 🔍 Top Threats")
    md_lines.append("")

    for art in sorted_articles[:10]:
        sev = score_severity(art)
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        tactics = ", ".join(art.get("mitre_tactics", [])) or "—"
        keywords = ", ".join(art.get("matched_keywords", [])[:5]) or "—"
        md_lines.extend([
            f"### {emoji} {art['title']}",
            "",
            f"- **Source**: {art['source']}",
            f"- **Severity**: {sev.upper()}",
            f"- **MITRE Tactics**: {tactics}",
            f"- **Keywords**: {keywords}",
            f"- **Link**: [{art['link']}]({art['link']})",
            "",
            art.get("summary", "")[:300],
            "",
            "---",
            "",
        ])

    markdown = "\n".join(md_lines)

    # ── HTML (renderable, email-compatible) ───────────────────────────────────
    severity_bg = {"critical": "#ff4d4d", "high": "#ff8c00", "medium": "#ffd700", "low": "#87ceeb"}
    severity_fg = {"critical": "#fff", "high": "#fff", "medium": "#333", "low": "#333"}

    article_rows = []
    for art in sorted_articles[:10]:
        sev = score_severity(art)
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        bg = severity_bg.get(sev, "#ccc")
        fg = severity_fg.get(sev, "#000")
        tactics = ", ".join(art.get("mitre_tactics", [])) or "—"
        keywords = ", ".join(art.get("matched_keywords", [])[:5]) or "—"
        article_rows.append(f"""
        <tr>
          <td style="padding:16px;border-bottom:1px solid #eee;vertical-align:top;">
            <div style="font-size:20px;margin-bottom:6px;">{emoji}</div>
            <div style="font-size:14px;font-weight:bold;margin-bottom:4px;">
              <a href="{art['link']}" style="color:#1a73e8;text-decoration:none;">{art['title']}</a>
            </div>
            <div style="font-size:12px;color:#666;margin-bottom:8px;">{art['source']}</div>
            <span style="display:inline-block;padding:2px 10px;border-radius:12px;background:{bg};color:{fg};font-size:11px;font-weight:bold;">{sev.upper()}</span>
            <div style="font-size:12px;color:#555;margin-top:8px;">
              <strong>MITRE:</strong> {tactics} &nbsp;|&nbsp; <strong>Keywords:</strong> {keywords}
            </div>
          </td>
        </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Daily Threat Intel — {date_str}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 720px; margin: 0 auto; padding: 24px; background: #f9f9f9; }}
    .header {{ background: linear-gradient(135deg, #1a73e8, #0d47a1); color: white; padding: 28px 32px; border-radius: 12px; margin-bottom: 28px; }}
    .header h1 {{ margin: 0; font-size: 22px; }}
    .header p {{ margin: 8px 0 0; opacity: 0.9; font-size: 13px; }}
    .summary {{ background: white; padding: 20px 24px; border-radius: 10px; border-left: 4px solid #1a73e8; margin-bottom: 28px; white-space: pre-wrap; font-size: 14px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    td {{ padding: 16px 20px; border-bottom: 1px solid #f0f0f0; }}
    tr:last-child td {{ border-bottom: none; }}
    .footer {{ margin-top: 32px; text-align: center; font-size: 12px; color: #999; }}
    a {{ word-break: break-all; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ Daily Threat Intel — {date_str}</h1>
    <p>Automated daily briefing from 9 leading security news sources.</p>
  </div>
  <div class="summary">{summary.replace(chr(10), "<br>")}</div>
  <table>
    <tbody>{"".join(article_rows)}</tbody>
  </table>
  <div class="footer">
    Generated automatically on {date_str} UTC.<br>
    <a href="https://github.com/ara-5/Money-Threat-intel" style="color:#1a73e8;">Threat Intel Feed</a>
  </div>
</body>
</html>"""

    # ── Save to disk ──────────────────────────────────────────────────────────
    md_path = os.path.join(NEWSLETTER_DIR, f"{file_date}.md")
    html_path = os.path.join(NEWSLETTER_DIR, f"{file_date}.html")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(markdown)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    latest_md = os.path.join(NEWSLETTER_DIR, "latest.md")
    latest_html = os.path.join(NEWSLETTER_DIR, "latest.html")
    with open(latest_md, "w", encoding="utf-8") as f:
        f.write(markdown)
    with open(latest_html, "w", encoding="utf-8") as f:
        f.write(html)

    log.info("✓ Newsletter saved → %s + %s", md_path, html_path)
    return markdown, html


# ── Email Delivery (Gmail SMTP) ───────────────────────────────────────────────
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT   = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER   = os.getenv("SMTP_USER")
SMTP_PASS   = os.getenv("SMTP_PASS")


def send_email(to_addr: str, subject: str, html_body: str):
    """Send a single email via Gmail SMTP. Requires SMTP_USER and SMTP_PASS env vars."""
    if not SMTP_USER or not SMTP_PASS:
        log.info("SMTP credentials not configured — skipping email to %s", to_addr)
        return

    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import smtplib

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_addr
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [to_addr], msg.as_string())
        log.info("✓ Email sent to %s", to_addr)
    except Exception as e:
        log.error("✗ Email error for %s: %s", to_addr, e)


def send_newsletter_emails(html_body: str, articles: list[dict]):
    """Send newsletter HTML to all subscribers loaded from env var SUBSCRIBERS_JSON_B64."""
    subs_b64 = os.getenv("SUBSCRIBERS_JSON_B64")
    if not subs_b64:
        log.info("SUBSCRIBERS_JSON_B64 not set — skipping email broadcast.")
        return

    try:
        subs_json = base64.b64decode(subs_b64).decode("utf-8")
        subs_data = json.loads(subs_json)
        subscribers = subs_data.get("subscribers", [])
    except Exception as e:
        log.error("Failed to load subscribers from SUBSCRIBERS_JSON_B64: %s", e)
        return

    date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")
    subject = f"🛡️ Daily Threat Intel — {date_str}"
    count = 0
    for sub in subscribers:
        email = sub.get("email")
        tier = sub.get("tier", "free")
        if not email:
            continue
        send_email(email, subject, html_body)
        count += 1
    log.info("✓ Email broadcast complete — %d emails sent", count)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 60)
    log.info("🤖 Threat Intel Automation  —  %s UTC", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"))
    log.info("=" * 60)

    conn = init_db()
    purge_old(conn)

    articles  = fetch_articles(conn)
    filtered  = filter_articles(articles)

    if not filtered:
        log.info("No new threats found. Exiting.")
        conn.close()
        return

    # Score severities for logging
    for a in filtered:
        a["severity"] = score_severity(a)

    log.info("\n🔍 Top threats:")
    for a in filtered[:5]:
        log.info("  [%s] %s — %s", a["severity"].upper(), a["title"], a["source"])

    summary = summarize(filtered)
    log.info("\n📝 Summary:\n%s\n", summary)

    # Distribute
    send_to_discord(summary, filtered)
    send_to_slack(summary, filtered)
    save_json_report(summary, filtered)
    newsletter_md, newsletter_html = generate_newsletter(summary, filtered)
    send_newsletter_emails(newsletter_html, filtered)

    # Mark all as seen AFTER successful send
    for a in filtered:
        mark_seen(conn, a["link"], a["title"])
    conn.close()

    log.info("=" * 60)
    log.info("✅ Done — %d threats reported", len(filtered))
    log.info("=" * 60)


if __name__ == "__main__":
    main()
