"""
Tests for threat_intel.py
Run with: pytest tests/ -v
"""

import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from threat_intel import (
    init_db, is_seen, mark_seen, purge_old,
    filter_articles, detect_mitre, score_severity,
    summarize_fallback,
)

# ── DB tests ─────────────────────────────────────────────────────────────────

def make_mem_db():
    """In-memory SQLite for testing."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE seen (
            url TEXT PRIMARY KEY,
            title TEXT,
            seen_at TEXT
        )
    """)
    conn.commit()
    return conn


def test_seen_roundtrip():
    conn = make_mem_db()
    url = "https://example.com/article-1"
    assert not is_seen(conn, url)
    mark_seen(conn, url, "Test article")
    assert is_seen(conn, url)


def test_duplicate_mark_is_safe():
    conn = make_mem_db()
    url = "https://example.com/dup"
    mark_seen(conn, url, "First")
    mark_seen(conn, url, "Second")   # should not raise
    assert is_seen(conn, url)


def test_purge_removes_old_entries():
    import sqlite3 as sq
    from datetime import datetime, timedelta, timezone

    conn = make_mem_db()
    old_time = (datetime.now(timezone.utc) - timedelta(days=35)).replace(tzinfo=None).isoformat()
    conn.execute("INSERT INTO seen VALUES (?, ?, ?)", ("https://old.com", "old", old_time))
    conn.commit()

    purge_old(conn, days=30)
    assert not is_seen(conn, "https://old.com")


# ── Filter tests ──────────────────────────────────────────────────────────────

SAMPLE_ARTICLES = [
    {
        "source": "Test",
        "title": "Critical zero-day exploit found in Apache",
        "link": "https://example.com/1",
        "summary": "Attackers are actively exploiting a remote code execution vulnerability.",
        "published": "",
    },
    {
        "source": "Test",
        "title": "Company releases quarterly earnings report",
        "link": "https://example.com/2",
        "summary": "Revenue up 12% year over year.",
        "published": "",
    },
    {
        "source": "Test",
        "title": "Ransomware gang targets healthcare sector",
        "link": "https://example.com/3",
        "summary": "A new ransomware variant with worm-like spreading capability was detected.",
        "published": "",
    },
]


def test_filter_keeps_threats():
    result = filter_articles(SAMPLE_ARTICLES)
    links = [a["link"] for a in result]
    assert "https://example.com/1" in links
    assert "https://example.com/3" in links


def test_filter_drops_non_threats():
    result = filter_articles(SAMPLE_ARTICLES)
    links = [a["link"] for a in result]
    assert "https://example.com/2" not in links


def test_filter_attaches_keywords():
    result = filter_articles(SAMPLE_ARTICLES)
    for art in result:
        assert "matched_keywords" in art
        assert len(art["matched_keywords"]) > 0


def test_filter_attaches_mitre():
    result = filter_articles(SAMPLE_ARTICLES)
    for art in result:
        assert "mitre_tactics" in art


# ── MITRE tagging tests ───────────────────────────────────────────────────────

def test_mitre_rce_detected():
    tactics = detect_mitre("remote code execution vulnerability in windows")
    assert "Execution" in tactics


def test_mitre_ransomware_detected():
    tactics = detect_mitre("ransomware group encrypts hospital files")
    assert "Impact" in tactics


def test_mitre_phishing_detected():
    tactics = detect_mitre("phishing campaign targeting executives")
    assert "Initial Access" in tactics


def test_mitre_empty_on_benign():
    tactics = detect_mitre("the stock market rose today")
    assert tactics == []


# ── Severity scoring tests ────────────────────────────────────────────────────

def test_severity_critical():
    art = {"title": "zero-day actively exploited in Chrome", "summary": "RCE in the wild"}
    assert score_severity(art) == "critical"


def test_severity_high():
    art = {"title": "New malware campaign discovered", "summary": "backdoor planted on servers"}
    assert score_severity(art) == "high"


def test_severity_medium():
    art = {"title": "Patch Tuesday: 40 vulnerabilities fixed", "summary": "CVE-2024-1234 advisory"}
    assert score_severity(art) == "medium"


def test_severity_low():
    art = {"title": "Cybersecurity conference announced", "summary": "industry event next month"}
    assert score_severity(art) == "low"


# ── Fallback summary tests ────────────────────────────────────────────────────

def test_fallback_summary_no_articles():
    from threat_intel import summarize
    result = summarize([])
    assert "no" in result.lower() or "✅" in result


def test_fallback_summary_has_counts():
    articles = filter_articles(SAMPLE_ARTICLES)
    result = summarize_fallback(articles)
    assert "threat" in result.lower() or "detected" in result.lower()
