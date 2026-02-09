import ipaddress
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "leakbase.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.create_function("ip_to_int", 1, ip_to_int)
    return conn


def ip_to_int(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return int(ipaddress.IPv4Address(value))
    except Exception:
        return None


def init_db(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY,
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
            hash TEXT UNIQUE
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_domain_norm ON records(domain_norm)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_login_norm ON records(login_norm)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_email_norm ON records(email_norm)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_email_domain_norm ON records(email_domain_norm)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_url_norm ON records(url_norm)"
    )
    conn.commit()
