# Armorer contributor instructions

Read `/Users/bluby/.codex/RTK.md` when working on the owner's workstation and prefix shell commands with rtk.

- Use Veans project 16 for task tracking; distinguish project indexes from database IDs and read back writes.
- v0.1 targets SLSA Build L2. Level 3 is deferred to a future-version backlog item.
- Keep implementation in isolated branches/worktrees. Preserve unrelated changes and never modify pilot repositories incidentally.
- Build, format, lint and run meaningful tests before committing/pushing. Do not merge or publish releases without explicit human authorization.
- Check/plan discovery must not execute repository build scripts or change consuming files. Report capability limitations; never silently downgrade verification.
- Never request or expose credential values. Do not expose shell/custom-provenance inputs in reusable builders.
