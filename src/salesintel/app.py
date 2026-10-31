"""Sales desk over the scored account mart."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from salesintel.score import CLASS_LABEL

WEB_DIR = Path(__file__).resolve().parents[2] / "web"
QUEUE_RANK = {"now": 0, "month": 1, "nurture": 2}

app = FastAPI(title="Signalboard")
_DB: Path | None = None


def _conn() -> sqlite3.Connection:
    if _DB is None or not _DB.exists():
        raise HTTPException(status_code=500, detail="Database has not been built yet")
    conn = sqlite3.connect(_DB)
    conn.row_factory = sqlite3.Row
    return conn


def _filters(
    q: str,
    queue: str,
    kind: str,
    country: str,
    klass: str,
    min_priority: int,
) -> tuple[str, list]:
    clauses = ["priority >= ?"]
    params: list = [min_priority]
    if queue:
        if queue not in QUEUE_RANK:
            raise HTTPException(status_code=400, detail="unknown queue")
        clauses.append("queue = ?")
        params.append(queue)
    if kind:
        if kind not in ("domain", "org", "ip"):
            raise HTTPException(status_code=400, detail="unknown kind")
        clauses.append("kind = ?")
        params.append(kind)
    if country:
        clauses.append("country = ?")
        params.append(country.upper())
    if klass:
        if klass not in CLASS_LABEL:
            raise HTTPException(status_code=400, detail="unknown class")
        clauses.append("classes LIKE ?")
        params.append(f'%"{klass}"%')
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{escaped}%"
        clauses.append(
            "(name LIKE ? ESCAPE '\\' OR IFNULL(domain,'') LIKE ? ESCAPE '\\' "
            "OR IFNULL(org_hint,'') LIKE ? ESCAPE '\\' OR account_key LIKE ? ESCAPE '\\' "
            "OR why_now LIKE ? ESCAPE '\\')"
        )
        params.extend([like, like, like, like, like])
    return " AND ".join(clauses), params


def _account_dict(row: sqlite3.Row) -> dict:
    data = dict(row)
    data["classes"] = json.loads(data["classes"])
    data["breakdown"] = json.loads(data["breakdown"])
    data["class_labels"] = [CLASS_LABEL.get(item, item) for item in data["classes"]]
    return data


@app.get("/api/health")
def health():
    return {"ok": True, "db": str(_DB) if _DB else None}


@app.get("/api/stats")
def stats():
    conn = _conn()
    meta_row = conn.execute("SELECT v FROM meta WHERE k = 'ingest'").fetchone()
    meta = json.loads(meta_row["v"]) if meta_row else {}
    counts = {
        "accounts": conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()["n"],
        "findings": conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"],
        "by_queue": {
            row["queue"]: row["n"]
            for row in conn.execute("SELECT queue, COUNT(*) AS n FROM accounts GROUP BY queue")
        },
        "by_kind": {
            row["kind"]: row["n"]
            for row in conn.execute("SELECT kind, COUNT(*) AS n FROM accounts GROUP BY kind")
        },
    }
    countries = [
        {"country": row["country"], "n": row["n"]}
        for row in conn.execute(
            "SELECT country, COUNT(*) AS n FROM accounts WHERE country != '' "
            "GROUP BY country ORDER BY n DESC LIMIT 30"
        )
    ]
    conn.close()
    return {"meta": meta, "counts": counts, "countries": countries, "classes": CLASS_LABEL}


@app.get("/api/accounts")
def accounts(
    q: str = "",
    queue: str = "",
    kind: str = "",
    country: str = "",
    klass: str = "",
    min_priority: int = 0,
    page: int = Query(1, ge=1),
    page_size: int = Query(40, ge=1, le=100),
):
    where, params = _filters(q, queue, kind, country, klass, min_priority)
    conn = _conn()
    total = conn.execute(f"SELECT COUNT(*) AS n FROM accounts WHERE {where}", params).fetchone()["n"]
    offset = (page - 1) * page_size
    rows = conn.execute(
        f"SELECT * FROM accounts WHERE {where} ORDER BY priority DESC, finding_count DESC LIMIT ? OFFSET ?",
        [*params, page_size, offset],
    ).fetchall()
    conn.close()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "accounts": [_account_dict(row) for row in rows],
    }


@app.get("/api/account")
def account(key: str):
    conn = _conn()
    row = conn.execute("SELECT * FROM accounts WHERE account_key = ?", (key,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="account not found")
    findings = [
        dict(item)
        for item in conn.execute(
            "SELECT * FROM findings WHERE account_key = ? ORDER BY points DESC",
            (key,),
        )
    ]
    conn.close()
    payload = _account_dict(row)
    payload["findings"] = findings
    return payload


@app.get("/api/export.csv")
def export_csv(
    q: str = "",
    queue: str = "",
    kind: str = "",
    country: str = "",
    klass: str = "",
    min_priority: int = 0,
):
    where, params = _filters(q, queue, kind, country, klass, min_priority)
    conn = _conn()
    rows = conn.execute(
        f"SELECT name, domain, kind, country, queue, priority, pain, why_now, org_hint, asn, ip_count "
        f"FROM accounts WHERE {where} ORDER BY priority DESC LIMIT 5000",
        params,
    ).fetchall()
    conn.close()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["name", "domain", "kind", "country", "queue", "priority", "pain", "why_now", "network", "asn", "ips"])
    for row in rows:
        writer.writerow([row[col] for col in row.keys()])
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=signalboard.csv"},
    )


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


def build_app(db_path: Path) -> FastAPI:
    global _DB
    _DB = db_path
    return app


def main(argv: list[str] | None = None) -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="Serve the Signalboard desk")
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    build_app(Path(args.db))
    if WEB_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
