# 🛡️ Automated Threat Intelligence Feed

> **Fully automated, zero-cost AI-powered cybersecurity threat intelligence pipeline.**
> Collects, deduplicates, scores, MITRE-tags, and distributes high-risk security news daily — with no human intervention and no paid APIs.

![Tests](https://github.com/ara-5/Automated-threat-intel-feed/actions/workflows/tests.yml/badge.svg)
![Daily Run](https://github.com/ara-5/Automated-threat-intel-feed/actions/workflows/threat_intel.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Cost](https://img.shields.io/badge/cost-$0%2Fmonth-brightgreen)

---

## 📋 What It Does

| Feature | Detail |
|---|---|
| **Data Sources** | 9 free RSS feeds: THN, BleepingComputer, Dark Reading, Krebs, Schneier, CISA, SecurityWeek, Naked Security, Threatpost |
| **Deduplication** | SQLite DB remembers seen articles; never re-reports the same story |
| **Filtering** | 22 threat keywords covering zero-days, ransomware, CVEs, APTs, and more |
| **Severity Scoring** | Heuristic engine classifies every article as 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low |
| **MITRE ATT&CK Tagging** | Auto-maps articles to tactics: Initial Access, Execution, Impact, etc. |
| **AI Summary** | Llama 3 70B via Groq free API — 120-word analyst-style daily briefing |
| **Distribution** | Rich Discord embeds + optional Slack webhook |
| **JSON Archive** | Machine-readable report saved to `docs/` on every run — acts as a free REST API via GitHub Pages |
| **Scheduling** | GitHub Actions cron — runs daily at 07:00 UTC, completely free |

---

## 🖼️ Sample Output

```
🛡️ Daily Threat Intel — June 01, 2025

📊 ANALYST BRIEFING
Three critical threats dominate today's feed. A zero-day RCE in Apache HTTP
Server (CVE-2025-1234) is being actively exploited against unpatched 2.4.x
installations — patch immediately. A new LockBit variant is targeting healthcare
and finance sectors with double-extortion tactics; indicators of compromise are
available from CISA advisory AA25-152A. Additionally, a credential-stuffing
campaign exploiting leaked combo lists is hitting Microsoft 365 tenants.
Recommended actions: apply Apache patch, enable MFA on M365, block LockBit IOCs.

Severity Breakdown: 🔴 CRITICAL: 2   🟠 HIGH: 5   🟡 MEDIUM: 6

────────────────────────────────────────────────
🔴 Zero-day RCE in Apache HTTP Server (CISA)
   Severity: CRITICAL | MITRE: Initial Access, Execution
   Keywords: zero-day, remote code execution, cve-

🔴 LockBit variant targets hospitals (BleepingComputer)
   Severity: CRITICAL | MITRE: Impact, Lateral Movement
   Keywords: ransomware, exfiltration, lateral movement

🟠 Credential stuffing campaign against M365 (Krebs on Security)
   Severity: HIGH | MITRE: Credential Access, Initial Access
   Keywords: credential, breach, phishing
────────────────────────────────────────────────
```

---

## 🚀 Quick Start (5 minutes)

### 1. Fork this repository

Click **Fork** at the top of this page.

### 2. Get your free Groq API key

Sign up at [console.groq.com](https://console.groq.com) — **no credit card required**.
Copy your API key.

### 3. Create a Discord webhook

In your Discord server: **Server Settings → Integrations → Webhooks → New Webhook**.
Copy the webhook URL.

### 4. Add secrets to GitHub

Go to your forked repo → **Settings → Secrets and variables → Actions → New repository secret**.

| Secret name | Value |
|---|---|
| `GROQ_API_KEY` | Your Groq key from step 2 |
| `DISCORD_WEBHOOK` | Your Discord webhook URL from step 3 |
| `SLACK_WEBHOOK` | *(Optional)* Your Slack incoming webhook |

### 5. Enable Actions

Go to the **Actions** tab in your fork and click **"I understand my workflows, go ahead and enable them"**.

That's it. The pipeline runs every day at 07:00 UTC automatically.

### Run locally

```bash
git clone https://github.com/YOUR_USERNAME/Automated-threat-intel-feed
cd Automated-threat-intel-feed
pip install -r requirements.txt
cp .env.example .env   # fill in your keys
python threat_intel.py
```

---

## 🗂️ Project Structure

```
.
├── threat_intel.py              # Main pipeline
├── requirements.txt             # feedparser, requests, python-dotenv (all free)
├── .env.example                 # Environment variable template
├── .github/
│   └── workflows/
│       ├── threat_intel.yml     # Daily cron job
│       └── tests.yml            # CI — runs on every push
├── tests/
│   └── test_threat_intel.py     # Full test suite (pytest)
└── docs/
    ├── latest.json              # Always the most recent report (free API!)
    └── report_YYYY-MM-DD.json   # Historical archive
```

---

## 🧱 Architecture

```
GitHub Actions (cron 07:00 UTC)
        │
        ▼
  threat_intel.py
        │
        ├─ fetch_articles()   ← 9 RSS feeds, ~72 articles/day
        │       │
        │       └─ SQLite dedup  ← skip already-seen articles
        │
        ├─ filter_articles()  ← 22 threat keywords
        │
        ├─ score_severity()   ← Critical / High / Medium / Low
        │
        ├─ detect_mitre()     ← MITRE ATT&CK tactic mapping
        │
        ├─ summarize()        ← Groq Llama 3 (free) → fallback heuristic
        │
        ├─ send_to_discord()  ← Rich colour-coded embeds
        ├─ send_to_slack()    ← Optional
        └─ save_json_report() ← docs/latest.json + dated archive
```

---

## 💰 Free API Credits Breakdown

| Service | Free Tier | Usage |
|---|---|---|
| **Groq** | 14,400 requests/day, 500k tokens/day | ~300 tokens/day → **0.06% of limit** |
| **GitHub Actions** | 2,000 min/month | ~2 min/day → **3% of limit** |
| **Discord Webhooks** | Unlimited | — |
| **RSS Feeds** | All free/public | — |

**Monthly cost: $0.00**

---

## 🔌 The Free JSON API

Every daily report is committed to `docs/` and served via GitHub Pages as a free REST API.

Enable GitHub Pages: **Settings → Pages → Source: Deploy from branch `main` → `/docs`**

Then access:

```
# Latest report (always current)
https://YOUR_USERNAME.github.io/Automated-threat-intel-feed/latest.json

# Specific date
https://YOUR_USERNAME.github.io/Automated-threat-intel-feed/report_2025-06-01.json
```

This is your free public API that others can subscribe to.

---

## 💼 Monetization Roadmap

This project is a launchpad. Here's how to turn it into income:

### Tier 1 — Do this first (free, builds audience)

- **Publish a daily newsletter** on [Substack](https://substack.com) using the AI summary as the base content. Free to start; charge $5–9/month for the paid tier (raw JSON feed, custom keyword alerts, weekly deep-dives).
- **Post daily highlights** on LinkedIn/Twitter. Attach the report. Build a following in the infosec community. Consulting leads will follow.

### Tier 2 — Freelance / Consulting (no code changes needed)

- **Offer custom deployments** to small businesses and MSPs. Many companies want internal threat briefings but have no SOC. Charge $200–500/month per client. 5 clients = $1,000–2,500/month.
- **Use this as a portfolio piece** on Upwork/Fiverr to land SOC automation contracts ($50–150/hr).

### Tier 3 — SaaS (3–6 months of work)

- **Build a hosted version** at a domain like `threatdigest.io`:
  - Free tier: daily digest to one Discord/Slack channel
  - Pro ($15/mo): custom keyword watchlists, CVE tracking by vendor, Slack + email + Discord, API access
  - Team ($49/mo): multiple channels, white-label reports, team dashboard, webhook integrations
- **White-label for MSSPs**: Security service providers will pay $200–1,000/month for a branded version they resell to their own clients.

### Tier 4 — Data product

- The `docs/` JSON archive becomes a historical threat intelligence dataset over time. Security researchers, academics, and compliance teams pay for structured, deduplicated historical threat data. License it via [RapidAPI](https://rapidapi.com) or sell CSV exports.

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## 🤝 Contributing

Pull requests welcome. Please open an issue first for major changes.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/add-email-delivery`)
3. Commit your changes
4. Push and open a PR

---

## 📄 License

MIT — use it, modify it, sell it.
