# ChangeLog

This file summarizes the changed made on the original source code, as required
by the Apache 2.0 original license. Most recent changes are at the top.

See the git log for details about the changes (exact date, etc.).


## Fri, April 23, 2020

Remove clockwork dependency.

  - Remove `clock.go`
  - Modify `validate.go`: replace Clock type field in ValidationContext with a
    locally defined interface type
  - Add changelog 