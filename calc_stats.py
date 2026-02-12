import argparse
import json
import os
from pathlib import Path

from app import DATABASE_URL
from db import configure_database, db_execute, get_conn, init_db


def run_calculations(conn, sample_percent: float):
    base_from = "records"
    if sample_percent and sample_percent > 0:
        base_from = f"records TABLESAMPLE SYSTEM ({sample_percent})"
    print("этап 1/3: считаю общее количество записей", flush=True)
    total_records = db_execute(conn, f"SELECT COUNT(*) FROM {base_from}").fetchone()[0]
    print("этап 2/3: считаю логины в паролях", flush=True)
    contains_login_total = db_execute(
        conn,
        f"""
        SELECT COUNT(*)
        FROM {base_from}
        WHERE login IS NOT NULL
          AND password IS NOT NULL
          AND LENGTH(login) >= 4
          AND (
            POSITION(LOWER(login) IN LOWER(password)) > 0
            OR POSITION(LOWER(SUBSTRING(login FROM 1 FOR 4)) IN LOWER(password)) > 0
          )
        """
    ).fetchone()[0]
    percent = round((contains_login_total / total_records) * 100, 2) if total_records else 0
    print("этап 3/3: считаю топы", flush=True)
    top_patterns_rows = db_execute(
        conn,
        f"""
        SELECT pattern, COUNT(*) AS total
        FROM (
            SELECT CASE
                WHEN POSITION(LOWER(login) IN LOWER(password)) > 0
                    THEN REPLACE(LOWER(password), LOWER(login), '{{login}}')
                WHEN POSITION(LOWER(SUBSTRING(login FROM 1 FOR 4)) IN LOWER(password)) > 0
                    THEN REPLACE(LOWER(password), LOWER(SUBSTRING(login FROM 1 FOR 4)), '{{login4}}')
                ELSE NULL
            END AS pattern
            FROM {base_from}
            WHERE login IS NOT NULL
              AND password IS NOT NULL
              AND LENGTH(login) >= 4
        ) t
        WHERE pattern IS NOT NULL
        GROUP BY pattern
        ORDER BY total DESC
        LIMIT 50
        """
    ).fetchall()
    top_password_rows = db_execute(
        conn,
        f"""
        SELECT password, COUNT(*) AS total
        FROM {base_from}
        WHERE password IS NOT NULL AND password != ''
        GROUP BY password
        ORDER BY total DESC
        LIMIT 50
        """
    ).fetchall()
    return {
        "contains_login_total": contains_login_total,
        "contains_login_percent": f"{percent}%",
        "sample_percent": sample_percent,
        "top_patterns": [
            {"pattern": pattern, "count": count} for pattern, count in top_patterns_rows
        ],
        "top_passwords_50": [
            {"password": password, "count": count} for password, count in top_password_rows
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="calculations.json",
        help="Путь к файлу результата",
    )
    parser.add_argument(
        "--sample-percent",
        type=float,
        default=0,
        help="Процент сэмпла TABLESAMPLE SYSTEM",
    )
    parser.add_argument(
        "--connect-timeout",
        type=int,
        default=10,
        help="Таймаут подключения к базе (секунды)",
    )
    parser.add_argument(
        "--db-url",
        default="",
        help="Строка подключения к базе, если нужно переопределить",
    )
    parser.add_argument(
        "--skip-init",
        action="store_true",
        help="Не выполнять init_db (ускоряет, если БД уже подготовлена)",
    )
    args = parser.parse_args()

    print("подключение к базе", flush=True)
    db_url = args.db_url or os.getenv("DATABASE_URL", DATABASE_URL)
    print(f"db_url: {db_url}", flush=True)
    configure_database(db_url)
    try:
        conn = get_conn(connect_timeout=args.connect_timeout)
    except Exception as exc:
        raise SystemExit(f"ошибка подключения: {exc}")
    print("подключение установлено", flush=True)
    if args.skip_init:
        print("инициализация пропущена", flush=True)
    else:
        print("инициализация схемы", flush=True)
        init_db(conn)
        print("инициализация завершена", flush=True)
    try:
        data = run_calculations(conn, args.sample_percent)
    finally:
        conn.close()
    output_path = Path(args.output)
    if output_path.parent and not output_path.parent.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"готово: {output_path}", flush=True)


if __name__ == "__main__":
    main()
