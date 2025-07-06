from flask import Flask, render_template_string, redirect, url_for
import storage, datetime as dt

app = Flask(__name__)

PAGE = """
<!doctype html><html lang=en><meta charset=utf-8>
<title>SecOps Intel – Test Dashboard</title>
<link rel=stylesheet href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
<main class="container">
  <h1>📣 Latest LinkedIn Articles ({{ posts|length }} shown)</h1>
  {% if not posts %}
      <p><em>No posts yet.</em></p>
  {% else %}
      {% for p in posts %}
      <article>
        <header><h3>{{ p.title }}</h3>
        <small>Published {{ p.ts }}</small></header>
        <details><summary>Preview</summary>
          <div>{{ p.html|safe }}</div>
        </details>
      </article>
      {% endfor %}
  {% endif %}
  <form method="post" action="{{ url_for('clear') }}">
    <button class="contrast">🧹 Clear Log</button>
  </form>
</main>"""

@app.get("/")
def index():
    return render_template_string(PAGE, posts=storage.latest(5))

@app.post("/clear")
def clear():
    storage.clear()
    return redirect(url_for("index"))

@app.get("/health")
def health():
    return {"status": "ok", "utc": dt.datetime.utcnow().isoformat()}
