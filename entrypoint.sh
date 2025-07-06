#!/bin/sh
set -e

# ── schedule the crawler ────────────────────────────────────────────────────
echo "${CRON_SCHEDULE} python /app/fetch_high_cvss.py >> /proc/1/fd/1 2>&1" \
  > /etc/cron.d/high-cvss
chmod 0644 /etc/cron.d/high-cvss
crontab /etc/cron.d/high-cvss

# Run cron in background
cron

# ── start the Flask UI via Gunicorn ─────────────────────────────────────────
exec gunicorn -b 0.0.0.0:${PORT} app:app
