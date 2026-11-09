"""Alembic environment. Usage: AEGISCHAIN_DATABASE_URL=postgresql+psycopg://... alembic -c database/alembic.ini upgrade head"""

import os

from alembic import context
from sqlalchemy import create_engine

url = os.environ.get("AEGISCHAIN_DATABASE_URL")
if not url:
    raise SystemExit("AEGISCHAIN_DATABASE_URL must be set")

if context.is_offline_mode():
    context.configure(url=url, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    with create_engine(url).connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()
