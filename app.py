"""
Run with:  python app.py
Shows the latest 5 LinkedIn articles and lets you clear the log.

If you DON'T need the dashboard in production, skip deploying this
component and just schedule fetch_high_cvss.py in Choreo.
"""
from flask import Flask, render_template_string, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
import storage, fetch_high_cvss, datetime as dt, os

PORT = int(os.getenv("PORT", "8080"))
app  = Flask(__name__)

# ── background job (runs once a day in container time) ───────────────────
sched = BackgroundScheduler(timezone="UTC", daemon=True)
sched.add_job(fetch_high_cvss.main, "cron", hour=3, minute=0)  # 03:00 UTC
sched.start()

HTML = """
<!doctype html><html><head><meta charset=utf-8>
<title>SecOps Intel Dashboard</title>
<link rel=stylesheet href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
</head><body><main class=container>
<h1>Latest LinkedIn Articles ({{ posts|length }})</h1>
{% if not posts %}
  <p><em>No posts yet.</em></p>
{% else %}
  {% for p in posts %}
  <article>
    <header><h3>{{ p.title }}</h3><small>{{ p.ts }}</small></header>
    <details><summary>Show preview</summary>
      <div>{{ p.html|safe }}</div>
    </details>
  </article>
  {% endfor %}
{% endif %}
<form method=post action="{{ url_for('clear') }}">
  <button class=contrast>🧹 Clear Log</button>
</form>
</main></body></html>"""

@app.get("/")
def index():
    return render_template_string(HTML, posts=storage.latest(5))

@app.post("/clear")
def clear():
    storage.clear()
    return redirect(url_for("index"))

@app.get("/health")
def health():
    return {"status": "ok", "utc": dt.datetime.utcnow().isoformat()}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
