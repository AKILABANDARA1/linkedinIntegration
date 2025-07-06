"""
Very small helper for persisting the last N LinkedIn posts to disk
as line‑delimited JSON objects (posts.jsonl).
"""
import json, pathlib, typing as _t

STORE = pathlib.Path("/app/posts.jsonl")
STORE.parent.mkdir(exist_ok=True)

def append(record: dict) -> None:
    with STORE.open("a", encoding="utf‑8") as fp:
        fp.write(json.dumps(record, ensure_ascii=False) + "\n")

def latest(n: int = 5) -> list[dict]:
    if not STORE.exists():
        return []
    with STORE.open(encoding="utf‑8") as fp:
        lines = fp.readlines()[-n:]
    return [json.loads(line) for line in reversed(lines)]

def clear() -> None:
    STORE.unlink(missing_ok=True)
