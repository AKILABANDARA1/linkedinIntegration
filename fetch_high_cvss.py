#!/usr/bin/env python
"""
Daily CVE hunter:
• Scans multiple security‑news RSS feeds for CVE IDs.
• Queries NVD for CVSS; keeps only those ≥ MIN_SCORE.
• Crafts an interactive, SEO‑tuned LinkedIn article.
• Logs each published article for the Flask UI.
"""
import os, re, sys, json, logging, datetime as dt
import requests, feedparser, storage

RSS_URLS   = [u.strip() for u in os.getenv("RSS_URLS", "").split(",") if u.strip()]
MIN_SCORE  = float(os.getenv("MIN_SCORE", 8.0))
NVD_API_KEY= os.getenv("NVD_API_KEY")
LI_TOKEN   = os.getenv("LINKEDIN_ACCESS_TOKEN")       # required to post
LI_AUTHOR  = os.getenv("LINKEDIN_AUTHOR_URN")         # "urn:li:organization:…"
CVE_RE     = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

log = logging.getLogger("high_cvss")
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")

def feed_entries():
    for url in RSS_URLS:
        for entry in feedparser.parse(url).entries:
            yield entry

def unique(seq):
    seen = set()
    for x in seq:
        if x not in seen:
            seen.add(x); yield x

def cvss_score(cve: str) -> float | None:
    api = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}"
    hdrs= {"User-Agent": "SecOpsIntelBot/1.1"}
    if NVD_API_KEY: hdrs["apiKey"] = NVD_API_KEY
    try:
        r = requests.get(api, headers=hdrs, timeout=12).json()
        item = r["result"]["CVE_Items"][0]["impact"]
        if "baseMetricV3" in item:
            return item["baseMetricV3"]["cvssV3"]["baseScore"]
        if "baseMetricV2" in item:
            return item["baseMetricV2"]["cvssV2"]["baseScore"]
    except Exception as e:
        log.warning(f"⚠️  NVD lookup failed for {cve}: {e}")
    return None

def linkedin_post(title: str, html_body: str) -> None:
    headers = {
        "Authorization": f"Bearer {LI_TOKEN}",
        "X-Restli-Protocol-Version": "2.0.0",
        "Content-Type": "application/json",
    }
    payload = {
      "author": LI_AUTHOR,
      "lifecycleState": "PUBLISHED",
      "specificContent": { "com.linkedin.article.Article":
            { "title": title, "content": html_body } },
      "visibility": { "com.linkedin.article.MemberNetworkVisibility": "PUBLIC" }
    }
    r = requests.post("https://api.linkedin.com/v2/articles",
                      headers=headers, data=json.dumps(payload), timeout=20)
    if r.status_code not in (201,202):
        raise RuntimeError(f"LinkedIn error {r.status_code}: {r.text}")
    log.info(f"✅ LinkedIn article posted ({r.status_code})")

def main():
    high = []
    for e in feed_entries():
        text = f"{e.title} {e.get('summary','')}"
        for cve in unique(CVE_RE.findall(text)):
            score = cvss_score(cve)
            if score and score >= MIN_SCORE:
                high.append({"cve": cve.upper(),
                             "score": score,
                             "title": e.title,
                             "link": e.link})
    if not high:
        log.info("No CVEs ≥ %.1f today." % MIN_SCORE); return

    today = dt.datetime.utcnow().strftime("%B %d, %Y")
    title = f"🔥 Critical CVEs ({today}) — Patch Now & Stay Safe"  # SEO‑rich

    intro = (
      f"<p>Security teams, brace yourselves! "
      f"We’ve spotted <strong>{len(high)} brand‑new CVEs scoring {MIN_SCORE}+ "
      f"on the CVSS v3 scale</strong>. Quick rundown below — full technical "
      f"details, exploitability insights, and mitigation tips inside.</p>"
    )
    bullets = "".join(
      f"<li><strong>{h['cve']}</strong> — {h['title']} "
      f"(CVSS {h['score']}) "
      f"<a href=\"{h['link']}\">Read source</a></li>"
      for h in high)
    cta = (
      "<p>🚀  Hungry for step‑by‑step exploit demos, YARA/Sigma rules, "
      "and blue‑team detection logic? "
      "<a href=\"https://t.me/secopsintel\">Join our SecOps Intel community</a> "
      "and level up!</p>"
    )
    body = f"{intro}<ul>{bullets}</ul>{cta}"

    if not (LI_TOKEN and LI_AUTHOR):
        log.warning("LinkedIn env vars missing – dumping article:\n%s", body)
    else:
        linkedin_post(title, body)

    # Persist for the Flask UI
    storage.append({"ts": dt.datetime.utcnow().isoformat(timespec='seconds'),
                    "title": title, "html": body})

if __name__ == "__main__":
    main()
