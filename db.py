import ipaddress

try:
    import psycopg
except Exception:
    psycopg = None

DATABASE_URL = ""


def configure_database(url: str):
    global DATABASE_URL
    DATABASE_URL = url.strip()


def adapt_query(query: str):
    return query.replace("?", "%s")


def db_execute(conn, query: str, params=None):
    if params is None:
        return conn.execute(adapt_query(query))
    return conn.execute(adapt_query(query), params)


def db_executemany(conn, query: str, params):
    cursor = conn.cursor()
    cursor.executemany(adapt_query(query), params)
    return cursor


def insert_statement():
    return """
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
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (hash) DO NOTHING
    """


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    if psycopg is None:
        raise RuntimeError("psycopg is not installed")
    return psycopg.connect(DATABASE_URL)


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
            id BIGSERIAL PRIMARY KEY,
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
        """
        CREATE OR REPLACE FUNCTION ip_to_int(value text) RETURNS bigint AS $$
        BEGIN
            IF value ~ '^\\d{1,3}(\\.\\d{1,3}){3}$' THEN
                RETURN (split_part(value, '.', 1)::bigint << 24)
                    + (split_part(value, '.', 2)::bigint << 16)
                    + (split_part(value, '.', 3)::bigint << 8)
                    + split_part(value, '.', 4)::bigint;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql IMMUTABLE;
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_domain_norm ON records(domain_norm) WHERE length(domain_norm) <= 512"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_login_norm ON records(login_norm) WHERE length(login_norm) <= 512"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_email_norm ON records(email_norm) WHERE length(email_norm) <= 512"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_email_domain_norm ON records(email_domain_norm) WHERE length(email_domain_norm) <= 512"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_records_url_norm ON records(url_norm) WHERE length(url_norm) <= 512"
    )
    conn.commit()
