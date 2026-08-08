//! Install a consistent FTS-free Go SQLite snapshot as the Rust state DB.

use std::future::Future;
use std::path::PathBuf;
use std::task::{Context, Waker};

use yuhaiin_store::install_go_snapshot_with_manifest;

fn main() {
    let (source, destination) = match parse_args() {
        Ok(paths) => paths,
        Err(message) => {
            eprintln!("go-snapshot-migrate: {message}");
            eprintln!("usage: go-snapshot-migrate --source FILE --destination FILE");
            std::process::exit(2);
        }
    };

    let manifest = std::path::PathBuf::from(format!("{}.manifest.json", source.display()));
    match block_on(install_go_snapshot_with_manifest(
        &source,
        &destination,
        &manifest,
    )) {
        Ok(report) => println!(
            "yuhaiin-rust-migration-ok source_bytes={} destination_bytes={} destination={}",
            report.source_bytes,
            report.destination_bytes,
            destination.display()
        ),
        Err(error) => {
            eprintln!("go-snapshot-migrate: {}", error.message);
            std::process::exit(1);
        }
    }
}

fn parse_args() -> Result<(PathBuf, PathBuf), String> {
    let mut source = None;
    let mut destination = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--source") => source = args.next().map(PathBuf::from),
            Some("--destination") => destination = args.next().map(PathBuf::from),
            Some(value) => return Err(format!("unknown argument {value}")),
            None => return Err("argument is not valid UTF-8".to_owned()),
        }
    }
    match (source, destination) {
        (Some(source), Some(destination)) => Ok((source, destination)),
        _ => Err("both --source and --destination are required".to_owned()),
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}
