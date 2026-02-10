Howto

Postgres через Docker

1) Запуск базы:
docker compose up -d postgres

2) Импорт данных в Postgres:
docker compose run --rm ingest

Postgres без Docker

1) Проверь строку подключения в app.py (DATABASE_URL)

2) Импорт данных в Postgres:
python /opt/my-tools/leakbase/ingest.py --recursive
