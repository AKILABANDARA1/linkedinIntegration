########## build stage #######################################################
ARG PY_VERSION=3.12.4
FROM python:${PY_VERSION}-slim-bookworm AS build

# Needed to compile some wheels (if any) — keep it slim
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends build-essential ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

COPY . .

########## final (runtime) stage #############################################
# Start FROM the *same* Python tag so ABI matches, but we install nothing here.
FROM python:${PY_VERSION}-slim-bookworm

# ── patch OS packages to latest security versions ───────────────────────────
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ── copy site‑packages from build stage only (no compilers) ─────────────────
COPY --from=build /install /usr/local
COPY --from=build /app /app

# ── create & switch to non‑root user (UID/GID 10001) ────────────────────────
RUN groupadd -g 10001 appuser && \
    useradd  -u 10001 -g appuser -s /usr/sbin/nologin -m appuser
USER 10001

WORKDIR /app
EXPOSE 8080

# Default command = Flask dashboard; override in Choreo schedule for crawler
CMD ["python", "app.py"]
