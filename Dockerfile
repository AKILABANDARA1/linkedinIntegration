# ---------- build stage -------------------------------------------------
FROM python:3.12-slim AS base

WORKDIR /app

# Install CA certificates (SSL fix) – build‑time only
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy & install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create an unprivileged user (UID/GID 10001)
RUN groupadd -g 10001 appuser && \
    useradd  -u 10001 -g appuser -s /bin/sh -m appuser

# Switch to the non‑root user for runtime
USER 10001

EXPOSE 8080          # Flask UI port (adjust in app.py if you wish)

# Default command = Flask dashboard.
# For the scheduled crawler, point Choreo's schedule to:
#   python /app/fetch_high_cvss.py
CMD ["python", "app.py"]
