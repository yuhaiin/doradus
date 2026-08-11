//! Compare a mature SQLite backend against the current pure-Rust backend on a
//! real snapshot without modifying the source database.

use std::path::PathBuf;
use std::time::Instant;

use rusqlite::{Connection, OptionalExtension};

fn main() {
    let (source, destination, print_schema) = match parse_args() {
        Ok(paths) => paths,
        Err(message) => {
            eprintln!("sqlite-backend-probe: {message}");
            eprintln!(
                "usage: sqlite_backend_probe --source FILE --destination FILE [--print-schema]"
            );
            std::process::exit(2);
        }
    };

    if !source.is_file() {
        fail(format!("source does not exist: {}", source.display()));
    }
    if destination.exists() {
        fail(format!(
            "refusing to overwrite destination: {}",
            destination.display()
        ));
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create destination directory: {error}")));
    }

    let started = Instant::now();
    std::fs::copy(&source, &destination)
        .unwrap_or_else(|error| fail(format!("copy source snapshot: {error}")));
    let copy_elapsed = started.elapsed();

    let connection_started = Instant::now();
    let connection = Connection::open(&destination)
        .unwrap_or_else(|error| fail(format!("open SQLite destination: {error}")));
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .unwrap_or_else(|error| fail(format!("set SQLite busy timeout: {error}")));
    connection
        .execute_batch(
            "PRAGMA cache_size = -32768;
             PRAGMA temp_store = FILE;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .unwrap_or_else(|error| fail(format!("configure SQLite connection: {error}")));
    let configure_elapsed = connection_started.elapsed();

    let schema_version: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap_or_else(|error| fail(format!("read schema version: {error}")));
    let fakeip_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM fakeip_entries", [], |row| row.get(0))
        .unwrap_or_else(|error| fail(format!("count FakeIP rows: {error}")));
    let nodes: i64 = connection
        .query_row("SELECT COUNT(*) FROM nodes_v2", [], |row| row.get(0))
        .unwrap_or_else(|error| fail(format!("count node rows: {error}")));
    if print_schema {
        print_schema_summary(&connection);
    }
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS yuhaiin_probe_meta (
                 key TEXT PRIMARY KEY NOT NULL,
                 value TEXT NOT NULL
             );
             INSERT OR REPLACE INTO yuhaiin_probe_meta(key, value)
                 VALUES ('backend', 'rusqlite-bundled');",
        )
        .unwrap_or_else(|error| fail(format!("write probe metadata: {error}")));
    connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_row| Ok(()))
        .unwrap_or_else(|error| fail(format!("checkpoint SQLite destination: {error}")));
    drop(connection);

    println!(
        "sqlite-backend-probe-ok backend=rusqlite-bundled schema={} fakeip_rows={} nodes={} copy_ms={} configure_ms={} {}",
        schema_version.as_deref().unwrap_or("missing"),
        fakeip_rows,
        nodes,
        copy_elapsed.as_millis(),
        configure_elapsed.as_millis(),
        memory_summary(),
    );
}

fn parse_args() -> Result<(PathBuf, PathBuf, bool), String> {
    let mut source = None;
    let mut destination = None;
    let mut print_schema = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--source") => source = args.next().map(PathBuf::from),
            Some("--destination") => destination = args.next().map(PathBuf::from),
            Some("--print-schema") => print_schema = true,
            Some(value) => return Err(format!("unknown argument {value}")),
            None => return Err("argument is not valid UTF-8".to_owned()),
        }
    }
    match (source, destination) {
        (Some(source), Some(destination)) => Ok((source, destination, print_schema)),
        _ => Err("both --source and --destination are required".to_owned()),
    }
}

fn print_schema_summary(connection: &Connection) {
    let mut statement = connection
        .prepare(
            "SELECT type, name
             FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name",
        )
        .unwrap_or_else(|error| fail(format!("prepare schema query: {error}")));
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap_or_else(|error| fail(format!("query schema objects: {error}")))
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap_or_else(|error| fail(format!("read schema objects: {error}")));
    let migrations = connection
        .prepare("SELECT version, name FROM migrate ORDER BY version")
        .ok()
        .and_then(|mut statement| {
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .ok()?;
            Some(
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap_or_else(|error| fail(format!("read migrations: {error}"))),
            )
        })
        .unwrap_or_default();
    println!("schema-objects={objects:?}");
    println!("migrations={migrations:?}");
}

fn memory_summary() -> String {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return "rss=unavailable".to_owned();
    };
    let values = ["VmPeak", "VmHWM", "VmRSS"]
        .into_iter()
        .filter_map(|key| {
            status.lines().find_map(|line| {
                line.strip_prefix(key)
                    .and_then(|line| line.trim().strip_prefix(':'))
                    .map(|value| format!("{key}={}", value.trim()))
            })
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        "rss=unavailable".to_owned()
    } else {
        values.join(",")
    }
}

fn fail(message: String) -> ! {
    eprintln!("sqlite-backend-probe: {message}");
    std::process::exit(1);
}
