# Doradus compatibility and future migration

Doradus is a new service with its own product identity, binary, service
identities, runtime paths, and state database. Doradus and existing service
installations must be treated as independent processes and installations.

## Current release boundary

- The main binary is `doradus`.
- The default HTTP API listener is `0.0.0.0:58080`.
- `-host`, `-path`, `-u`, `-p`, and `-q` are the supported startup controls.
- `-path DIR` stores the native database at `DIR/state.sqlite`.
- Native service names, paths, caches, and release artifacts use Doradus names.
- The update API currently reports that updates are unsupported.

The existing `/api/v2` routes, supported wire protocols, configuration shape,
and observable behavior remain the compatibility target. Compatibility here
means preserving those contracts; it does not mean sharing a live database or
service lifecycle.

## Database boundary

New Doradus installations create a Doradus-owned SQLite database with the
native `doradus_meta` and `doradus_config` tables. The default state file is
`state.sqlite`. A legacy database is not silently adopted by the new service.

The source contains legacy snapshot readers, schema validation, and import
helpers for a future explicit migration workflow. They are retained as
compatibility code, but no migration command is part of the current release.
Until that workflow is designed and tested, make a separate copy of legacy
state before any future migration experiment.

## Future migration design

When migration is eventually added, it must be an explicit, offline operation
with these boundaries:

1. Read a stopped legacy source or an exported snapshot.
2. Write a new Doradus database in a separate destination directory.
3. Validate the source schema and each preserved protocol/configuration
   contract before committing the destination.
4. Keep unknown fields and unsupported records recoverable rather than silently
   discarding them.
5. Never overwrite the source or make two runtimes write the same SQLite file.
6. Require an operator-selected cutover after the result has been inspected.

The migration implementation should also document field-level differences,
source and destination checksums, failure recovery, and the compatibility
version of every imported record before it is exposed as a supported workflow.

## Service and release installation

Build the release binary with the workspace tooling and install it as an
independent `doradus` service. Supply the new data directory and listener
explicitly when integrating with a service manager:

~~~bash
./target/release/doradus install \
  -host 0.0.0.0:58080 \
  -path /var/lib/doradus
~~~

Use the matching Doradus `health`, `start`, `stop`, and `restart` commands for
that installation. Do not point those commands at an old service's state or
unit directory.

For compatibility comparisons, use separate copies of the source data and
separate listener addresses. The Go compatibility harness may retain its
historical internal listener on `50051`; Doradus uses `58080`.
