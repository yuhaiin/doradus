#!/usr/bin/env python3
"""Audit the SQLite schema retained by the Rust compatibility projection.

Both databases are opened immutable/read-only.  Rust may add compatibility
objects or migrate rows, so this audit requires every source object and every
source table definition to survive, while reporting (rather than rejecting)
row-count and semantic-content changes caused by projection/migration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any


# These Go tables are intentionally replaced by Rust's typed compatibility
# schema during compatibility projection. Their names and rows must remain addressable, but
# their legacy column/index layout is expected to change.
EXPECTED_SCHEMA_MIGRATIONS = frozenset(
    {
        "dns_resolvers",
        "failure_dimension_hourly",
        "route_rules",
        "traffic_dimension_hourly",
    }
)

SEMANTIC_NORMALIZATIONS = (
    "telemetry_dimension_values.id (surrogate key)",
    "statistics_kv.updated_at (projection timestamp)",
    "traffic_hourly.updated_at (projection timestamp)",
    "connection_history.last_connection_json (canonical JSON key order)",
)


def quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def connect(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise SystemExit(f"missing SQLite snapshot: {path}")
    connection = sqlite3.connect(
        f"file:{path}?mode=ro&immutable=1",
        uri=True,
    )
    connection.execute("PRAGMA query_only = ON")
    return connection


def inventory(connection: sqlite3.Connection) -> dict[tuple[str, str], tuple[str, str | None]]:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
          AND type IN ('table', 'index', 'trigger', 'view')
        ORDER BY type, name
        """
    )
    return {(kind, name): (table, kind) for kind, name, table in rows}


def table_columns(connection: sqlite3.Connection, table: str) -> list[tuple[Any, ...]]:
    return [
        tuple(row)
        for row in connection.execute(
            f"PRAGMA table_info({quoted_identifier(table)})"
        )
    ]


def table_indexes(connection: sqlite3.Connection, table: str) -> dict[str, tuple[Any, ...]]:
    indexes: dict[str, tuple[Any, ...]] = {}
    for sequence, name, unique, origin, partial in connection.execute(
        f"PRAGMA index_list({quoted_identifier(table)})"
    ):
        if str(name).startswith("sqlite_autoindex"):
            continue
        columns = tuple(
            row[2]
            for row in connection.execute(
                f"PRAGMA index_info({quoted_identifier(name)})"
            )
        )
        indexes[str(name)] = (int(unique), str(origin), int(partial), columns)
    return indexes


def normalized_value(value: Any) -> Any:
    """Return a deterministic JSON representation for SQLite values."""

    if isinstance(value, bytes):
        return {"blob_sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
    if isinstance(value, memoryview):
        raw = value.tobytes()
        return {"blob_sha256": hashlib.sha256(raw).hexdigest(), "length": len(raw)}
    return value


def canonical_row_values(
    table: str, columns: list[tuple[Any, ...]], row: tuple[Any, ...]
) -> list[list[Any]]:
    """Project volatile/surrogate fields away while retaining row semantics."""

    values: list[list[Any]] = []
    for column, value in zip(columns, row):
        name = str(column[1])
        if table == "telemetry_dimension_values" and name == "id":
            # Rust may allocate compact dimension ids in a different order;
            # the durable key is (dimension, value), not the surrogate id.
            continue
        if table in {"statistics_kv", "traffic_hourly"} and name == "updated_at":
            # Projection time is necessarily different for a new database.
            continue
        if table == "connection_history" and name == "last_connection_json":
            if isinstance(value, str):
                try:
                    value = {"json": json.loads(value)}
                except json.JSONDecodeError:
                    pass
        values.append([name, normalized_value(value)])
    return values


def row_digest(
    connection: sqlite3.Connection, table: str
) -> tuple[int, str]:
    """Hash semantic rows in a stable order without loading a table into memory."""

    columns = table_columns(connection, table)
    primary_key = [str(row[1]) for row in columns if int(row[5]) > 0]
    if table == "telemetry_dimension_values":
        order_by = '"dimension", "value"'
        query = (
            f"SELECT * FROM {quoted_identifier(table)} "
            f"ORDER BY {order_by}"
        )
    elif primary_key:
        order_by = ", ".join(quoted_identifier(column) for column in primary_key)
        query = (
            f"SELECT * FROM {quoted_identifier(table)} "
            f"ORDER BY {order_by}"
        )
    else:
        order_by = ", ".join(quoted_identifier(str(row[1])) for row in columns)
        query = (
            f"SELECT * FROM {quoted_identifier(table)} "
            f"ORDER BY {order_by}"
        )

    digest = hashlib.sha256()
    count = 0
    for row in connection.execute(query):
        encoded = json.dumps(
            canonical_row_values(table, columns, row),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    return count, digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--prepared", type=Path, required=True)
    args = parser.parse_args()

    source = connect(args.source)
    prepared = connect(args.prepared)
    try:
        source_objects = inventory(source)
        prepared_objects = inventory(prepared)
        missing_objects = sorted(
            key
            for key in set(source_objects) - set(prepared_objects)
            if source_objects[key][0] not in EXPECTED_SCHEMA_MIGRATIONS
            or key[0] == "table"
        )
        if missing_objects:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "source objects missing after Rust compatibility projection",
                        "missing": [list(item) for item in missing_objects],
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1

        column_diffs: dict[str, Any] = {}
        index_diffs: dict[str, Any] = {}
        migrated_schema_diffs: dict[str, Any] = {}
        migrated_object_diffs: dict[str, Any] = {}
        row_diffs: dict[str, list[int]] = {}
        row_content_diffs: dict[str, Any] = {}
        migrated_row_content_diffs: dict[str, Any] = {}
        for key in sorted(set(source_objects) & set(prepared_objects)):
            source_table = source_objects[key][0]
            prepared_table = prepared_objects[key][0]
            if source_table == prepared_table:
                continue
            if key[0] == "index" and source_table in EXPECTED_SCHEMA_MIGRATIONS:
                migrated_object_diffs[key[1]] = {
                    "source_table": source_table,
                    "prepared_table": prepared_table,
                }
            else:
                column_diffs[f"object:{key[0]}:{key[1]}"] = {
                    "source_table": source_table,
                    "prepared_table": prepared_table,
                }
        source_tables = sorted(name for kind, name in source_objects if kind == "table")
        for table in source_tables:
            source_columns = table_columns(source, table)
            prepared_columns = table_columns(prepared, table)
            if source_columns != prepared_columns:
                target = migrated_schema_diffs if table in EXPECTED_SCHEMA_MIGRATIONS else column_diffs
                target[table] = {
                    "source": source_columns,
                    "prepared": prepared_columns,
                }

            source_indexes = table_indexes(source, table)
            prepared_indexes = table_indexes(prepared, table)
            missing_indexes = sorted(set(source_indexes) - set(prepared_indexes))
            changed_indexes = sorted(
                name
                for name in set(source_indexes) & set(prepared_indexes)
                if source_indexes[name] != prepared_indexes[name]
            )
            if missing_indexes or changed_indexes:
                target = migrated_schema_diffs if table in EXPECTED_SCHEMA_MIGRATIONS else index_diffs
                target.setdefault(table, {})["indexes"] = {
                    "missing": missing_indexes,
                    "changed": changed_indexes,
                }

            source_count, source_digest = row_digest(source, table)
            prepared_count, prepared_digest = row_digest(prepared, table)
            if source_count != prepared_count:
                row_diffs[table] = [source_count, prepared_count]
            if source_digest != prepared_digest:
                target = (
                    migrated_row_content_diffs
                    if table in EXPECTED_SCHEMA_MIGRATIONS
                    else row_content_diffs
                )
                target[table] = {
                    "source_count": source_count,
                    "prepared_count": prepared_count,
                    "source_sha256": source_digest,
                    "prepared_sha256": prepared_digest,
                }

        if column_diffs or index_diffs:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "SQLite schema changed during Rust compatibility projection",
                        "column_diffs": column_diffs,
                        "index_diffs": index_diffs,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1

        additional_objects = sorted(set(prepared_objects) - set(source_objects))
        report = {
            "ok": True,
            "source": str(args.source),
            "prepared": str(args.prepared),
            "source_objects": len(source_objects),
            "source_tables": len(source_tables),
            "preserved_objects": len(source_objects),
            "additional_objects": [list(item) for item in additional_objects],
            "expected_schema_migrations": sorted(EXPECTED_SCHEMA_MIGRATIONS),
            "schema_migration_object_diffs": migrated_object_diffs,
            "schema_migration_diffs": migrated_schema_diffs,
            "row_count_diffs": row_diffs,
            "row_content_diffs": row_content_diffs,
            "schema_migration_row_content_diffs": migrated_row_content_diffs,
            "row_digest": "sha256(length-prefixed-json-rows)",
            "semantic_normalizations": list(SEMANTIC_NORMALIZATIONS),
        }
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    finally:
        source.close()
        prepared.close()


if __name__ == "__main__":
    raise SystemExit(main())
