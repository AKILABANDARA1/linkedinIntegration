#!/usr/bin/env python
"""
High‑CVSS CVE Hunter & LinkedIn Publisher
----------------------------------------
• Scans security RSS feeds for CVE IDs
• Looks up CVSS v3 (or v2) **and** full text description on NVD
• (Optional) Summarises the description with OpenAI to be more LinkedIn‑friendly
• Generates an SEO‑rich LinkedIn article with a CTA to https://t.me/secopsintel
• Saves each post in posts.jsonl for the Flask dashboard
• DRY_RUN flag lets you populate the dashboard without live data

Environment variables
---------------------
RSS_URLS                Comma‑separated list of RSS feeds
MIN_SCORE               Minimum CVSS to include (default 8.0)
LINKEDIN_ACCESS_TOKEN   Token with w_member_social / w_organization_social
LINKEDIN_AUTHOR_URN     urn:li:person:… or urn:li:organization:…
NVD_API_KEY             Optional – bumps NVD rate limit
OPENAI_API_KEY          Optional – enables GPT re‑write of descriptions
DRY_RUN                 "true" → inject a fake CVE (default: false)

This file replaces the earlier fetch_high_cvss.py 100 %.
"""

from __future__ import annotations
import os, re, sys, json, logging, datetime as dt, textwrap
import requests, feedparser, storage

# ── Optional GPT summary
try:
    import openai
except ImportError:
    openai = None   # Only used if OPENAI_API_KEY is set

# ───── Config ──────────────────────────────────────────────────────────────
RSS_URLS   = [u.strip() for u in os.getenv("RSS_URLS", "").split(",") if u.strip()]
MIN_SCORE  = float(os.getenv("MIN_SCORE", 8.0))
DRY_RUN    = os.getenv("DRY_RUN", "false").lower() == "true"

NVD_API_KEY = os.getenv("NVD_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

LI_TOKEN  = os.getenv("LINKEDIN_ACCESS_TOKEN")
LI_AUTHOR = os.getenv("LINKEDIN_AUTHOR_URN")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

log = logging.getLogger("high_cvss")
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")

# ── Helper functions ───────────────────────────────────────────────────────

def feed_entries():
    for url in RSS_URLS:
        for entry in feedparser.parse(url).entries:
            yield entry

def unique(seq):
    seen = set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            yield x

def nvd_lookup(cve: str) -> tuple[float | None, str | None]:
    """Return (score, description) or (None, None)"""
    api = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}"
    hdrs = {"User-Agent": "SecOpsIntelBot/2.0"}
    if NVD_API_KEY:
        hdrs["apiKey"] = NVD_API_KEY
    try:
        r = requests.get(api, headers=hdrs, timeout=15)
        r.raise_for_status()
        data = r.json()["result"]["CVE_Items"][0]
        impact = data.get("impact", {})
        if "baseMetricV3" in impact:
            score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
        elif "baseMetricV2" in impact:
            score = impact["baseMetricV2"]["cvssV2"]["baseScore"]
        else:
            score = None
        desc = (
            data["cve"]["description"]["description_data"][0]["value"]
            if data["cve"]["description"]["description_data"] else ""
        )
        return score, desc
    except Exception as e:
        log.warning(f"⚠️  NVD lookup failed for {cve}: {e}")
        return None, None

def gpt_blurb(cve: str, raw_desc: str, score: float) -> str:
    if not (OPENAI_API_KEY and openai):
        # Fallback: first 60 words of NVD description
        return " ".join(raw_desc.split()[:60]) + "…"
    openai.api_key = OPENAI_API_KEY
    prompt = (
        "Rewrite the following CVE description for a LinkedIn audience. "
        "Make it engaging but concise (max 80 words), mention the CVSS "
        f"score {score}, and include one short call‑to‑action to patch.\n\n"
        f"CVE ID: {cve}\nDescription: {raw_desc}"
    )
    try:
        resp = openai.chat.completions.create(
            model="gpt-4o-mini", messages=[{"role":"user","content":prompt}],
            max_tokens=120, temperature=0.7
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        log.warning(f"OpenAI summary failed ({e}); using raw description.")
        return " ".join(raw_desc.split()[:80]) + "…"

def linkedin_post(title: str, html_body: str):
    headers = {
        "Authorization": f"Bearer {LI_TOKEN}",
        "X-Restli-Protocol-Version": "2.0.0",
        "Content-Type": "application/json",
    }
    payload = {
        "author": LI_AUTHOR,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.article.Article": {
                "title": title,
                "content": html_body
            }
        },
        "visibility": {
            "com.linkedin.article.MemberNetworkVisibility": "PUBLIC"
        }
    }
    r = requests.post("https://api.linkedin.com/v2/articles",
                      headers=headers, data=json.dumps(payload), timeout=20)
    if r.status_code not in (201, 202):
        raise RuntimeError(f"LinkedIn error {r.status_code}: {r.text}")
    log.info(f"✅ LinkedIn article posted ({r.status_code})")

# ───── Main ────────────────────────────────────────────────────────────────

def main():
    high = []

    if DRY_RUN:
        log.info("🧪 DRY_RUN enabled – injecting fake CVE.")
        high.append({
            "cve": "CVE-2025-9999",
            "score": 9.8,
            "blurb": "A test RCE in LazyApp lets attackers execute code remotely. "
                     "Patch immediately or disable the vulnerable module.",
            "link": "https://example.com/cve-2025-9999"
        })
    else:
        for entry in feed_entries():
            text = f"{entry.title} {entry.get('summary', '')}"
            for cve in unique(CVE_RE.findall(text)):
                score, desc = nvd_lookup(cve)
                if score and score >= MIN_SCORE:
                    blurb = gpt_blurb(cve, desc, score)
                    high.append({
                        "cve": cve.upper(),
                        "score": score,
                        "blurb": blurb,
                        "link": entry.link or f"https://nvd.nist.gov/vuln/detail/{cve}"
                    })

    if not high:
        log.info("No CVEs ≥ %.1f today." % MIN_SCORE)
        return

    # ── Build SEO‑friendly LinkedIn article ────────────────────────────────
    today = dt.datetime.utcnow().strftime("%B %d, %Y")
    title = f"🚨 {len(high)} Critical CVEs ({today}) — Patch Now"

    intro = textwrap.dedent(f"""
        <p><strong>Security teams, take note!</strong> We just spotted
        {len(high)} vulnerabilities scoring <em>{MIN_SCORE}+ on the CVSS scale</em>.
        Below is a quick rundown, a human‑friendly summary, and links to dive deeper.</p>
    """)

    bullet_html = "".join(
        f"<li><strong>{h['cve']}</strong> "
        f"(CVSS {h['score']}) – {h['blurb']} "
        f"<a href=\"{h['link']}\">Read more</a></li>"
        for h in high
    )

    cta = (
        "<p>🔒 For PoC exploits, Sigma/YARA detection rules and daily threat intel, "
        "join our community: "
        "<a href=\"https://t.me/secopsintel\">https://t.me/secopsintel</a></p>"
    )

    article = f"{intro}<ul>{bullet_html}</ul>{cta}"

    if LI_TOKEN and LI_AUTHOR and not DRY_RUN:
        linkedin_post(title, article)
    else:
        log.info("Preview (not posted):\n%s\n", article)

    # Persist for dashboard
    storage.append({
        "ts": dt.datetime.utcnow().isoformat(timespec='seconds'),
        "title": title,
        "html": article
    })

# ── Entrypoint ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
