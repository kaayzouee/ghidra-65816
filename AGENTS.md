# Agent instructions

Applies to the whole repository. Read `DEVELOPMENT.md` and `docs/SUPPORT.md` before changing behavior.

## Checks

```sh
python3 -m unittest discover --start-directory tests --verbose
bash scripts/ci/compile-sleigh.sh "$GHIDRA_INSTALL_DIR"
gradle test
```

Set `GHIDRA_INSTALL_DIR` to a supported Ghidra installation. Runtime tests also need the external module setup in `DEVELOPMENT.md`. CI is the compatibility gate for Ghidra 12.1, 12.1.2, 12.1.3, 12.1.4, and 12.2; report which checks actually ran. For disassembly or Ghidra-script changes, also run the relevant headless regression in `scripts/ci/test-*.py`.

## Repository layout

- `data/languages/`: 65816 SLEIGH, register/context definitions, and compiler specs.
- `src/test/`: Java P-code tests; `tests/`: source checks, fixtures, and headless scripts.
- `scripts/`: optional Ghidra scripts; `scripts/ci/`: CI runners.
- `docs/`, `README.md`, `DEVELOPMENT.md`: scope, limitations, and developer instructions.
- `.github/PULL_REQUEST_TEMPLATE.md`: required PR structure.

## Code and tests

- Keep changes small and focused. Prefer a short, straightforward method over extra helpers, abstractions, or broad refactoring. Do not copy whole implementations from a fork without reviewing them.
- Use supported, **non-deprecated** Ghidra/Java APIs. Check actual signatures and behavior against the Ghidra versions in CI; do not guess API names or rely on a newer version alone. Explain any unavoidable deprecated API use.
- Minimize comments. Use clear names and code structure instead; retain only required license/metadata annotations and explanations of genuinely non-obvious constraints. Do not narrate obvious operations or add decorative test comments.
- Add a minimal regression before fixing a verified bug. Cover both the intended change and cases that must remain unchanged. For CPU semantics, consult the W65C816S datasheet and independent evidence; compilation and passing tests alone are not proof of hardware correctness.
- Treat unknown or conflicting M/X/E, DBR, and control-flow state as unknown. Never invent a unique context at a branch join or call boundary.
- Prefer non-destructive diagnostics. Any script that clears/re-disassembles code must guard user context, labels, references, overrides, and overlapping code units; use transactions and fail closed.
- Treat imported ROM data as untrusted. An optional SNES loader must validate headers, file sizes, offsets, and bank mappings before creating memory blocks; test malformed and truncated inputs.

## Pull requests and scope

- Branch from the current upstream `master`, not an outdated fork branch. **One independent issue per PR**: separate fixtures, implementation, and unrelated features when they can be reviewed independently.
- Keep diffs minimal: no unrelated formatting, dead code, generated build outputs, or speculative enhancements. Update relevant documentation when behavior or limitations change.
- Run focused checks, then verify the complete CI matrix. Inspect failures rather than weakening assertions. Never claim tests passed if they were not run.
- **Squash each PR into one coherent commit before declaring it ready.** Check the final diff and rerun CI after the squash. Do not merge a PR unless explicitly requested.
- Respect `docs/SUPPORT.md`. SNES loading/mapping/vector discovery belongs in a separately scoped optional integration, not incidental CPU-module changes. Ghidra-core limitations cannot be claimed fixed by a SLEIGH-only workaround.
