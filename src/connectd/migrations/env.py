"""Alembic environment for the unified schema."""

import os

from alembic import context
from sqlalchemy import pool

from connectd.db import engine_for, metadata


config = context.config
target_metadata = metadata
database_url = os.environ.get("CONNECTD_DATABASE_URL") or config.get_main_option("sqlalchemy.url")


def run_migrations_offline():
    context.configure(url=database_url, target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    engine = engine_for(database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          render_as_batch=engine.dialect.name == "sqlite")
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
