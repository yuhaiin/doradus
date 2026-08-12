#!/usr/bin/env python3
"""Audit the SQLite schema retained by a Rust takeover of a Go snapshot.

Both databases are opened immutable/read-only.  Rust may add compatibility
objects or migrate rows, so this audit requires every source object and every
source table definition to survive, while reporting (rather than rejecting)
row-count changes caused by projection/migration.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any


# These Go tables are intentionally replaced by Rust's typed compatibility
# schema during takeover.  Their names and rows must remain addressable, but
# their legacy column/index layout is expected to change.
EXPECTED_SCHEMA_MIGRATIONS = frozenset(
    {
        "dns_resolvers",
        "failure_dimension_hourly",
        "route_rules",
        "traffic_dimension_hourly",
    }
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


def row_count(connection: sqlite3.Connection, table: str) -> int:
    return int(
        connection.execute(
            f"SELECT count(*) FROM {quoted_identifier(table)}"
        ).fetchone()[0]
    )


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
                        "error": "source objects missing after Rust takeover",
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

            source_count = row_count(source, table)
            prepared_count = row_count(prepared, table)
            if source_count != prepared_count:
                row_diffs[table] = [source_count, prepared_count]

        if column_diffs or index_diffs:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "SQLite schema changed during Rust takeover",
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
        }
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    finally:
        source.close()
        prepared.close()


if __name__ == "__main__":
    raise SystemExit(main())
