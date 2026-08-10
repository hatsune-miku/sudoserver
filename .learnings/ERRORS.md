# Errors

## [ERR-20260810-001] rg-no-match-exit-code

**Logged**: 2026-08-10T12:11:00+08:00
**Priority**: low
**Status**: resolved
**Area**: config

### Summary

An `rg` verification command with no matches returned exit code 1 and caused a parallel tool script to fail.

### Error

```text
Script error: Exit code: 1
```

### Context

- Several read-only `rg` checks were run through `Promise.all`.
- The first search intentionally had no matches after a successful refactor.

### Suggested Fix

When absence of matches is a successful verification result, wrap the command so exit code 1 is accepted or run searches independently.

### Metadata

- Reproducible: yes
- Related Files: none

### Resolution

- **Resolved**: 2026-08-10T12:11:00+08:00
- **Notes**: Subsequent no-match checks explicitly tolerate `rg` exit code 1.

---

## [ERR-20260810-004] assumed-debug-binary-after-tests

**Logged**: 2026-08-10T14:45:03+08:00
**Priority**: low
**Status**: resolved
**Area**: tests

### Summary

The CLI help check assumed `cargo test` had produced `target/debug/sudoserver.exe`.

### Error

```text
The term '.\target\debug\sudoserver.exe' is not recognized as an executable program.
```

### Context

- Unit-test binaries existed under `target/debug/deps`, but the normal CLI binary had not been built.

### Suggested Fix

Use `cargo run -- --help` or explicitly build the binary before invoking its expected path.

### Metadata

- Reproducible: yes
- Related Files: src/main.rs

### Resolution

- **Resolved**: 2026-08-10T14:45:03+08:00
- **Notes**: Switched the help verification to `cargo run`.

---

## [ERR-20260810-003] stale-mcp-safety-assertion

**Logged**: 2026-08-10T14:43:15+08:00
**Priority**: low
**Status**: resolved
**Area**: tests

### Summary

The MCP catalog test asserted an older safety sentence after the centralized wording had changed.

### Error

```text
assertion failed: text.contains("Never ask for the Master Password")
```

### Context

- The failure appeared while verifying the new uninstall command.
- Current MCP safety text lives across `SERVER_INSTRUCTIONS` and the centralized tool catalog.

### Suggested Fix

Assert the current centralized safety contract rather than an obsolete literal.

### Metadata

- Reproducible: yes
- Related Files: src/mcp.rs, src/mcp_text.rs

### Resolution

- **Resolved**: 2026-08-10T14:43:30+08:00
- **Notes**: Updated the test to validate the current server warning and sudo lecture.

---

## [ERR-20260810-002] assumed-dependency-module-path

**Logged**: 2026-08-10T14:40:33+08:00
**Priority**: low
**Status**: resolved
**Area**: backend

### Summary

A parallel dependency-source read assumed `windows-service` had a standalone `src/error.rs` file.

### Error

```text
Cannot find path '...windows-service-0.8.1\src\error.rs' because it does not exist.
```

### Context

- The uninstall example and crate sources were being inspected before implementing service removal.
- The crate exposes its error type from another module layout.

### Suggested Fix

List a dependency's source directory or use `rg` before reading a guessed module path.

### Metadata

- Reproducible: yes
- Related Files: src/main.rs

### Resolution

- **Resolved**: 2026-08-10T14:40:46+08:00
- **Notes**: Read the provided uninstall example and actual source directory instead.

---
