#!/usr/bin/env sh
set -e

# Read version from VERSION file if available, otherwise use APP_VERSION env var
if [ -f /app/VERSION ]; then
    VERSION=$(cat /app/VERSION | tr -d '\n\r ')
else
    VERSION=${APP_VERSION:-unknown}
fi

# Log version at startup
echo "Starting Open Port Monitor Backend version: ${VERSION}"

# Wait for database to be ready
echo "Waiting for database to be ready..."
uv run python /app/scripts/wait-for-db.py || exit 1

# Create all tables from models, then stamp alembic to head (skip migrations on fresh DB)
echo "Initializing database schema..."
cd /app && uv run python -c "
import sys; sys.path.insert(0, '/app/src')
from sqlalchemy import create_engine, text
from app.models import Base
import os
url = os.environ.get('DATABASE_URL', '').replace('+aiomysql', '+pymysql')
if not url:
    url = 'mysql+pymysql://{user}:{pw}@{host}:{port}/{db}'.format(
        user=os.environ.get('DB_USER','opm'),
        pw=os.environ.get('DB_PASSWORD','opm'),
        host=os.environ.get('DB_HOST','db'),
        port=os.environ.get('DB_PORT','3306'),
        db=os.environ.get('DB_NAME','openportmonitor'))
engine = create_engine(url)
with engine.begin() as conn:
    existing = set(row[0] for row in conn.execute(text('SHOW TABLES')))
    if 'alembic_version' not in existing:
        # Fresh DB: create all tables from models, then stamp
        print('Fresh database detected, creating all tables from models...')
        for table in Base.metadata.sorted_tables:
            if table.name not in existing:
                table.create(conn, checkfirst=False)
                print(f'  Created: {table.name}')
        fresh = True
    else:
        fresh = False
        print('Existing database, running migrations...')
engine.dispose()
if fresh:
    print('Stamping alembic to head...')
    import subprocess
    subprocess.run(['uv', 'run', 'alembic', 'stamp', 'head'], check=True)
else:
    import subprocess
    subprocess.run(['uv', 'run', 'alembic', 'upgrade', 'head'], check=True)
print('Database ready.')
"

# Initialize admin user BEFORE starting workers (single process, no race condition)
echo "Initializing admin user..."
uv run python /app/scripts/init_admin.py || exit 1

# Start application
exec uv run uvicorn src.app.main:app --host 0.0.0.0 --port 8000 --reload
