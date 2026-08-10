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
