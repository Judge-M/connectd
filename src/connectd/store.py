"""Transactional database access for SQLite and PostgreSQL."""

from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import URL, Connection as SAConnection

from connectd.db import engine_for, metadata




class Record:
    def __init__(self, row):
        self.row = row

    def __getitem__(self, key: int | str) -> Any:
        return self.row[key] if isinstance(key, int) else self.row._mapping[key]


class Result:
    def __init__(self, result):
        self.result = result
        self.rowcount = result.rowcount

    def fetchone(self) -> Record | None:
        row = self.result.fetchone()
        return Record(row) if row is not None else None

    def fetchall(self) -> list[Record]:
        return [Record(row) for row in self.result.fetchall()]

    def __iter__(self):
        for row in self.result:
            yield Record(row)


def _named(sql: str, params: tuple | list) -> tuple[str, dict]:
    parts = sql.split("?")
    if len(parts) - 1 != len(params):
        raise ValueError("SQL placeholder count does not match parameter count")
    statement = parts[0]
    values = {}
    for index, part in enumerate(parts[1:]):
        key = f"p{index}"
        statement += f":{key}" + part
        values[key] = params[index]
    return statement, values


class ManagedConnection:
    def __init__(self, store: "Store"):
        self.store = store
        self.connection: SAConnection | None = None
        self.transaction = None

    def __enter__(self):
        self.connection = self.store.engine.connect()
        self.transaction = self.connection.begin()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if self.transaction is not None and self.transaction.is_active:
                if exc_type is None:
                    self.transaction.commit()
                else:
                    self.transaction.rollback()
        finally:
            self.connection.close()

    def execute(self, sql: str, params: tuple | list = ()) -> Result:
        if sql.strip().upper() == "BEGIN IMMEDIATE":
            if self.store.engine.dialect.name == "sqlite":
                self.connection.exec_driver_sql("BEGIN IMMEDIATE")
            return Result(self.connection.execute(text("SELECT 1 WHERE 0=1")))
        statement, values = _named(sql, params)
        return Result(self.connection.execute(text(statement), values))

    def commit(self) -> None:
        if self.transaction is not None and self.transaction.is_active:
            self.transaction.commit()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if "://" in self.path:
            url = self.path
        else:
            url = URL.create("sqlite", database=self.path)
        self.engine = engine_for(url)

    def connect(self) -> ManagedConnection:
        return ManagedConnection(self)

    def initialize(self) -> None:
        metadata.create_all(self.engine)

    def dispose(self) -> None:
        self.engine.dispose()
