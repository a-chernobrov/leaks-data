import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlparse

from app import DATABASE_URL
from db import configure_database, db_execute, db_executemany, get_conn, init_db, insert_statement


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
    line = line.replace("\x00", "")
    line = line.strip()
    if not line:
        return None
    line = line.lstrip("\ufeff")
    parts = line.split(maxsplit=1)
    if len(parts) >= 2:
        url = parts[0].strip()
        cred = parts[1].strip()
        if ":" not in cred:
            if line.count(":") < 2:
                return None
            url, login, password = line.rsplit(":", 2)
        else:
            login, password = cred.split(":", 1)
    else:
        if line.count(":") < 2:
            return None
        url, login, password = line.rsplit(":", 2)
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


def format_bytes(value: int):
    size = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024


def report_progress(path: Path, file_done: int, file_size: int, total_done: int, total_size: int):
    if total_size > 0:
        print(
            f"  {path.name}: {format_bytes(file_done)}/{format_bytes(file_size)} | всего {format_bytes(total_done)}/{format_bytes(total_size)}",
            flush=True,
        )
    else:
        print(
            f"  {path.name}: {format_bytes(file_done)}/{format_bytes(file_size)}",
            flush=True,
        )


def ingest_file(conn, path: Path, batch_size: int, total_done: int, total_size: int, use_copy: bool):
    rows = []
    inserted = 0
    file_size = path.stat().st_size
    report_step = 5 * 1024 * 1024
    last_report = 0
    processed_bytes = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            processed_bytes += len(line.encode("utf-8", errors="ignore"))
            item = parse_line(line)
            if not item:
                continue
            rows.append(item)
            if len(rows) >= batch_size:
                inserted += insert_rows(conn, rows, use_copy)
                rows.clear()
                file_done = processed_bytes
                if file_done - last_report >= report_step:
                    report_progress(
                        path,
                        file_done,
                        file_size,
                        total_done + file_done,
                        total_size,
                    )
                    last_report = file_done
    if rows:
        inserted += insert_rows(conn, rows, use_copy)
    file_done = processed_bytes
    report_progress(
        path,
        file_done,
        file_size,
        total_done + file_done,
        total_size,
    )
    return inserted, file_done


def ensure_stage_table(conn):
    db_execute(
        conn,
        """
        CREATE TEMP TABLE IF NOT EXISTS records_stage (
            url TEXT,
            url_norm TEXT,
            domain TEXT,
            domain_norm TEXT,
            login TEXT,
            login_norm TEXT,
            email TEXT,
            email_norm TEXT,
            email_domain TEXT,
            email_domain_norm TEXT,
            password TEXT,
            hash TEXT
        )
        """,
    )


def copy_rows(conn, rows):
    cursor = conn.cursor()
    with cursor.copy(
        """
        COPY records_stage (
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
        ) FROM STDIN
        """
    ) as copy:
        for row in rows:
            copy.write_row(row)


def flush_stage(conn):
    cursor = db_execute(
        conn,
        """
        INSERT INTO records (
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
        )
        SELECT
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
        FROM records_stage
        ON CONFLICT (hash) DO NOTHING
        """
    )
    db_execute(conn, "TRUNCATE records_stage")
    conn.commit()
    return cursor.rowcount


def insert_rows(conn, rows, use_copy: bool):
    if use_copy:
        ensure_stage_table(conn)
        copy_rows(conn, rows)
        return flush_stage(conn)
    cursor = db_executemany(conn, insert_statement(), rows)
    conn.commit()
    return cursor.rowcount


def apply_fast_mode(conn):
    db_execute(conn, "SET synchronous_commit TO OFF")
    db_execute(conn, "SET maintenance_work_mem TO '1GB'")
    db_execute(conn, "SET temp_buffers TO '512MB'")
    db_execute(conn, "SET wal_compression TO on")


def drop_indexes(conn):
    db_execute(conn, "DROP INDEX IF EXISTS idx_records_domain_norm")
    db_execute(conn, "DROP INDEX IF EXISTS idx_records_login_norm")
    db_execute(conn, "DROP INDEX IF EXISTS idx_records_email_norm")
    db_execute(conn, "DROP INDEX IF EXISTS idx_records_email_domain_norm")
    db_execute(conn, "DROP INDEX IF EXISTS idx_records_url_norm")


def recreate_indexes(conn):
    db_execute(
        conn,
        "CREATE INDEX IF NOT EXISTS idx_records_domain_norm ON records(domain_norm) WHERE length(domain_norm) <= 512",
    )
    db_execute(
        conn,
        "CREATE INDEX IF NOT EXISTS idx_records_login_norm ON records(login_norm) WHERE length(login_norm) <= 512",
    )
    db_execute(
        conn,
        "CREATE INDEX IF NOT EXISTS idx_records_email_norm ON records(email_norm) WHERE length(email_norm) <= 512",
    )
    db_execute(
        conn,
        "CREATE INDEX IF NOT EXISTS idx_records_email_domain_norm ON records(email_domain_norm) WHERE length(email_domain_norm) <= 512",
    )
    db_execute(
        conn,
        "CREATE INDEX IF NOT EXISTS idx_records_url_norm ON records(url_norm) WHERE length(url_norm) <= 512",
    )
    conn.commit()


def use_unlogged(conn):
    db_execute(conn, "ALTER TABLE records SET UNLOGGED")


def use_logged(conn):
    db_execute(conn, "ALTER TABLE records SET LOGGED")


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
    parser.add_argument("--batch-size", type=int, default=20000)
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Ускоренный режим импорта (безопасность данных ниже)",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"Путь не найден: {root}")

    configure_database(DATABASE_URL)
    conn = get_conn()
    init_db(conn)
    if args.fast:
        drop_indexes(conn)
        apply_fast_mode(conn)
        use_unlogged(conn)

    files = list(iter_files(root, args.pattern, args.recursive))
    total_size = sum(path.stat().st_size for path in files)
    total_inserted = 0
    total_done = 0
    for index, path in enumerate(files, start=1):
        file_size = path.stat().st_size
        print(f"[{index}/{len(files)}] {path} ({format_bytes(file_size)})", flush=True)
        inserted, file_done = ingest_file(
            conn, path, args.batch_size, total_done, total_size, use_copy=True
        )
        total_done += file_done
        total_inserted += inserted
    if args.fast:
        use_logged(conn)
        recreate_indexes(conn)
    print(total_inserted)


if __name__ == "__main__":
    main()
