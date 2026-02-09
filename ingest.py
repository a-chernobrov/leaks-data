import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlparse

from db import get_conn, init_db


def normalize_url(value: str):
    raw = value.strip()
    if not raw:
        return "", "", "", ""
    norm = raw.lower()
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
    except Exception:
        host = ""
    return raw, norm, host, host.lower()


def parse_line(line: str):
    line = line.strip()
    if not line:
        return None
    parts = line.split(maxsplit=1)
    if len(parts) < 2:
        return None
    url = parts[0].strip()
    cred = parts[1].strip()
    if ":" not in cred:
        return None
    login, password = cred.split(":", 1)
    login = login.strip()
    password = password.strip()
    email = login if "@" in login else ""
    email_domain = email.split("@", 1)[1] if email else ""
    url_raw, url_norm, domain, domain_norm = normalize_url(url)
    login_norm = login.lower()
    email_norm = email.lower() if email else ""
    email_domain_norm = email_domain.lower() if email_domain else ""
    hash_value = hashlib.sha1(
        f"{url_norm}\t{login_norm}\t{password}".encode("utf-8", errors="ignore")
    ).hexdigest()
    return (
        url_raw,
        url_norm,
        domain,
        domain_norm,
        login,
        login_norm,
        email,
        email_norm,
        email_domain,
        email_domain_norm,
        password,
        hash_value,
    )


def iter_files(root: Path, pattern: str, recursive: bool):
    if root.is_file():
        yield root
        return
    if pattern:
        glob_pattern = f"**/{pattern}" if recursive else pattern
        iterator = root.glob(glob_pattern)
    else:
        iterator = root.rglob("*") if recursive else root.glob("*")
    for path in sorted(iterator):
        if path.is_file():
            yield path


def ingest_file(conn, path: Path, batch_size: int):
    rows = []
    inserted = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            item = parse_line(line)
            if not item:
                continue
            rows.append(item)
            if len(rows) >= batch_size:
                inserted += insert_rows(conn, rows)
                rows.clear()
    if rows:
        inserted += insert_rows(conn, rows)
    return inserted


def insert_rows(conn, rows):
    cursor = conn.executemany(
        """
        INSERT OR IGNORE INTO records (
            url,
            url_norm,
            domain,
            domain_norm,
            login,
            login_norm,
            email,
            email_norm,
            email_domain,
            email_domain_norm,
            password,
            hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    return cursor.rowcount


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        default="/opt/my-tools/leakbase/ULP",
        help="Путь к файлу или директории",
    )
    parser.add_argument(
        "--pattern",
        default="",
        help="Шаблон файлов, если пусто — все файлы",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Рекурсивный обход директорий",
    )
    parser.add_argument("--batch-size", type=int, default=2000)
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"Путь не найден: {root}")

    conn = get_conn()
    init_db(conn)

    total = 0
    for path in iter_files(root, args.pattern, args.recursive):
        total += ingest_file(conn, path, args.batch_size)
    print(total)


if __name__ == "__main__":
    main()
