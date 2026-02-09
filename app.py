import ipaddress
import re
from typing import List, Tuple
from urllib.parse import urlparse

from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from db import get_conn, init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = get_conn()
    init_db(conn)
    conn.close()
    yield


app = FastAPI(lifespan=lifespan)


def normalize_email_domain(value: str):
    value = value.strip()
    if value.startswith("@"):
        value = value[1:]
    return value.lower()


def url_filters(value: str) -> Tuple[str, List[str]]:
    value = value.strip().lower()
    candidate = value if "://" in value else f"http://{value}"
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
    except Exception:
        host = ""
    clauses = []
    args = []
    if host:
        clauses.append("domain_norm = ?")
        args.append(host.lower())
    clauses.append("url_norm = ?")
    args.append(value)
    if "://" in value or "/" in value:
        clauses.append("url_norm LIKE ?")
        args.append(value.rstrip("/") + "%")
    return "(" + " OR ".join(clauses) + ")", args


def ip_prefix_clause(value: str):
    value = value.strip().lower()
    if not value:
        return None
    if value.endswith(".*"):
        base = value[:-2]
        if re.match(r"^\d{1,3}(\.\d{1,3}){0,2}$", base):
            return "domain_norm LIKE ?", [base + ".%"]
    if value.endswith(".") and re.match(r"^\d{1,3}(\.\d{1,3}){0,3}\.$", value):
        return "domain_norm LIKE ?", [value + "%"]
    if "/" in value:
        ip, mask = value.split("/", 1)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            if mask == "32":
                return "domain_norm = ?", [ip]
            if mask == "8":
                return "domain_norm LIKE ?", [ip.split(".")[0] + ".%"]
            if mask == "16":
                parts = ip.split(".")
                return "domain_norm LIKE ?", [".".join(parts[:2]) + ".%"]
            if mask == "24":
                parts = ip.split(".")
                return "domain_norm LIKE ?", [".".join(parts[:3]) + ".%"]
        try:
            network = ipaddress.ip_network(value, strict=False)
        except Exception:
            return None
        start = int(network.network_address)
        end = int(network.broadcast_address)
        return "ip_to_int(domain_norm) BETWEEN ? AND ?", [start, end]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "domain_norm = ?", [value]
    return None


def tld_clause(value: str):
    value = value.strip().lower()
    if not value or not value.startswith("."):
        return None
    if len(value) < 2:
        return None
    if not re.match(r"^\.[a-z0-9-]{2,63}$", value):
        return None
    return "domain_norm LIKE ?", ["%"+value]


def detect_mode(value: str):
    value = value.strip()
    if not value:
        return None
    if ip_prefix_clause(value):
        return "ip"
    if tld_clause(value):
        return "tld"
    if value.startswith("@"):
        return "email_domain"
    if "@" in value:
        return "email"
    if "://" in value or "/" in value:
        return "url"
    if "." in value:
        return "url"
    return "login"


def build_query(
    url: str,
    email: str,
    login: str,
    email_domain: str,
    q: str,
    mode: str,
):
    clauses = []
    args = []
    if mode == "all":
        if not q:
            return "1=0", []
        value = q.strip().lower()
        email_domain_value = normalize_email_domain(q)
        ip_clause = ip_prefix_clause(q)
        tld_value = tld_clause(q)
        if ip_clause:
            url_clause, url_args = ip_clause
        elif tld_value:
            url_clause, url_args = tld_value
        else:
            url_clause, url_args = url_filters(q)
        clauses.append(
            f"({url_clause} OR login_norm = ? OR email_norm = ? OR email_domain_norm = ?)"
        )
        args.extend(url_args)
        args.extend([value, value, email_domain_value])
        return " AND ".join(clauses), args
    if url:
        ip_clause = ip_prefix_clause(url)
        if ip_clause:
            return ip_clause
        tld_value = tld_clause(url)
        if tld_value:
            return tld_value
        clause, args = url_filters(url)
        return clause, args
    if email:
        return "email_norm = ?", [email.strip().lower()]
    if login:
        return "login_norm = ?", [login.strip().lower()]
    if email_domain:
        return "email_domain_norm = ?", [normalize_email_domain(email_domain)]
    if q:
        detected = detect_mode(q)
        if detected == "ip":
            clause = ip_prefix_clause(q)
            if clause:
                return clause
        if detected == "tld":
            clause = tld_clause(q)
            if clause:
                return clause
        if detected == "url":
            clause, args = url_filters(q)
            return clause, args
        if detected == "email":
            return "email_norm = ?", [q.strip().lower()]
        if detected == "email_domain":
            return "email_domain_norm = ?", [normalize_email_domain(q)]
        return "login_norm = ?", [q.strip().lower()]
    return "1=0", []


@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8">
      <title>Leakbase Search</title>
      <style>
        :root {
          color-scheme: light;
        }
        body {
          margin: 0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
          background: #0f172a;
          color: #e2e8f0;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 24px;
        }
        .card {
          width: min(720px, 100%);
          background: #111827;
          border: 1px solid #1f2937;
          border-radius: 16px;
          padding: 28px;
          box-shadow: 0 12px 40px rgba(15, 23, 42, 0.45);
        }
        .title {
          font-size: 22px;
          font-weight: 600;
          margin-bottom: 6px;
        }
        .subtitle {
          font-size: 14px;
          color: #94a3b8;
          margin-bottom: 22px;
        }
        .search {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
        }
        .search input {
          flex: 1;
          min-width: 240px;
          background: #0b1220;
          border: 1px solid #1f2937;
          color: #e2e8f0;
          padding: 12px 14px;
          border-radius: 10px;
          font-size: 15px;
          outline: none;
        }
        .search button {
          background: #2563eb;
          color: #fff;
          border: none;
          padding: 12px 18px;
          border-radius: 10px;
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
        }
        .search button:hover {
          background: #1d4ed8;
        }
        .download {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          padding: 10px 14px;
          border-radius: 10px;
          border: 1px solid #1f2937;
          background: #0b1220;
          color: #e2e8f0;
          font-size: 13px;
          text-decoration: none;
          cursor: pointer;
        }
        .download.disabled {
          opacity: 0.5;
          pointer-events: none;
        }
        .stats {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          gap: 12px;
          margin-top: 20px;
        }
        .stat {
          background: #0b1220;
          border: 1px solid #1f2937;
          border-radius: 12px;
          padding: 14px;
        }
        .stat-label {
          font-size: 12px;
          color: #94a3b8;
          margin-bottom: 6px;
        }
        .stat-value {
          font-size: 18px;
          font-weight: 600;
        }
        .hint {
          margin-top: 18px;
          font-size: 12px;
          color: #64748b;
        }
        .results {
          margin-top: 18px;
          background: #0b1220;
          border: 1px solid #1f2937;
          border-radius: 12px;
          padding: 12px;
          max-height: 280px;
          overflow: auto;
        }
        .result-item {
          padding: 8px 10px;
          border-bottom: 1px solid #1f2937;
          font-size: 13px;
          color: #e2e8f0;
          word-break: break-all;
        }
        .result-item:last-child {
          border-bottom: none;
        }
        .result-empty {
          font-size: 13px;
          color: #94a3b8;
          padding: 6px 8px;
        }
        .result-meta {
          margin-top: 10px;
          font-size: 12px;
          color: #94a3b8;
        }
        .status {
          margin-top: 12px;
          font-size: 12px;
          color: #94a3b8;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .spinner {
          width: 12px;
          height: 12px;
          border: 2px solid #1f2937;
          border-top-color: #60a5fa;
          border-radius: 50%;
          animation: spin 0.9s linear infinite;
          display: none;
        }
        .spinner.active {
          display: inline-block;
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="title">Поиск утечек</div>
        <div class="subtitle">URL, email, логин, домен почты или IP</div>
        <div class="search">
          <input id="q" type="text" placeholder="Например: example.com или @mail.ru" />
          <button id="search">Искать</button>
          <a id="download" class="download disabled" href="#" download>Скачать все</a>
        </div>
        <div class="stats">
          <div class="stat">
            <div class="stat-label">Всего записей</div>
            <div class="stat-value" id="total">—</div>
          </div>
          <div class="stat">
            <div class="stat-label">Найдено по запросу</div>
            <div class="stat-value" id="count">—</div>
          </div>
        </div>
        <div class="hint">Первые 20. IP: 1.* / 1.1.* / 1.2.3.* / 1.2.3.0/24 / 1.0.0.0/18. TLD: .ru</div>
        <div class="results" id="results"></div>
        <div class="result-meta" id="result-meta"></div>
        <div class="status">
          <span class="spinner" id="spinner"></span>
          <span id="status-text"></span>
        </div>
      </div>
      <script>
        const input = document.getElementById("q")
        const btn = document.getElementById("search")
        const count = document.getElementById("count")
        const total = document.getElementById("total")
        const results = document.getElementById("results")
        const resultMeta = document.getElementById("result-meta")
        const download = document.getElementById("download")
        const spinner = document.getElementById("spinner")
        const statusText = document.getElementById("status-text")
        async function loadTotal() {
          const res = await fetch("/api/stats")
          const data = await res.json()
          total.textContent = data.total
        }
        function updateDownload(q) {
          if (!q) {
            download.href = "#"
            download.classList.add("disabled")
            return
          }
          download.href = `/api/download?q=${encodeURIComponent(q)}`
          download.classList.remove("disabled")
        }
        async function run() {
          const q = input.value.trim()
          if (!q) {
            count.textContent = "—"
            results.innerHTML = ""
            resultMeta.textContent = ""
            updateDownload("")
            statusText.textContent = ""
            spinner.classList.remove("active")
            return
          }
          updateDownload(q)
          statusText.textContent = "Поиск..."
          spinner.classList.add("active")
          const res = await fetch(`/api/search?q=${encodeURIComponent(q)}&include_items=true&limit=20&offset=0`)
          const data = await res.json()
          count.textContent = data.count
          if (!data.items || data.items.length === 0) {
            results.innerHTML = '<div class="result-empty">Совпадений нет</div>'
          } else {
            results.innerHTML = data.items.map((item) => {
              const url = item.url || ""
              const login = item.login || ""
              const password = item.password || ""
              return `<div class="result-item">${url} ${login}:${password}</div>`
            }).join("")
          }
          const shown = data.items ? data.items.length : 0
          resultMeta.textContent = `Показано ${shown} из ${data.count}`
          statusText.textContent = "Готово"
          spinner.classList.remove("active")
        }
        btn.addEventListener("click", run)
        input.addEventListener("keydown", (e) => {
          if (e.key === "Enter") run()
        })
        input.addEventListener("input", () => updateDownload(input.value.trim()))
        loadTotal()
      </script>
    </body>
    </html>
    """


@app.get("/api/search")
def search(
    url: str = Query(default=""),
    email: str = Query(default=""),
    login: str = Query(default=""),
    email_domain: str = Query(default=""),
    q: str = Query(default=""),
    mode: str = Query(default=""),
    limit: int = Query(default=50, ge=0, le=1000),
    offset: int = Query(default=0, ge=0),
    include_items: bool = Query(default=False),
):
    where, args = build_query(url, email, login, email_domain, q, mode)
    conn = get_conn()
    count = conn.execute(f"SELECT COUNT(*) FROM records WHERE {where}", args).fetchone()[0]
    items = []
    if include_items and limit > 0:
        conn.row_factory = lambda cursor, row: {
            "url": row[0],
            "login": row[1],
            "password": row[2],
        }
        rows = conn.execute(
            f"SELECT url, login, password FROM records WHERE {where} LIMIT ? OFFSET ?",
            args + [limit, offset],
        ).fetchall()
        items = rows
    conn.close()
    return JSONResponse({"count": count, "items": items})


@app.get("/api/stats")
def stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    conn.close()
    return JSONResponse({"total": total})


@app.get("/api/download")
def download_all(
    url: str = Query(default=""),
    email: str = Query(default=""),
    login: str = Query(default=""),
    email_domain: str = Query(default=""),
    q: str = Query(default=""),
    mode: str = Query(default=""),
):
    where, args = build_query(url, email, login, email_domain, q, mode)

    def generate():
        conn = get_conn()
        try:
            cursor = conn.execute(
                f"SELECT url, login, password FROM records WHERE {where}", args
            )
            while True:
                rows = cursor.fetchmany(2000)
                if not rows:
                    break
                for row in rows:
                    url_value = row[0] or ""
                    login_value = row[1] or ""
                    password_value = row[2] or ""
                    yield f"{url_value} {login_value}:{password_value}\n"
        finally:
            conn.close()

    headers = {"Content-Disposition": "attachment; filename=results.txt"}
    return StreamingResponse(generate(), media_type="text/plain", headers=headers)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000)
