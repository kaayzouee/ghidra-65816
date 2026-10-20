# Ghidra-65816: Limitations, Improvement Roadmap, and Ranked Resources

**Research date:** 2026-10-20  
**Target:** [`kaayzouee/ghidra-65816`](https://github.com/kaayzouee/ghidra-65816)  
**Scope:** Source and documentation review plus online research. This is a roadmap, not a claim that unexecuted tests passed.

## Executive assessment

The largest weakness is the gap between a processor specification that compiles and one proven to drive reliable disassembly, data-flow analysis, and decompilation across real 65816 programs. The repository is explicit that it is experimental, that static mode tracking is limited, and that its selected runtime cases do not prove complete processor correctness. The current development guide lists 24 runtime instruction sequences, which is useful progress but a small sample of a 256-opcode ISA with many addressing modes and multiple processor states.

The best route to improving the project's status is therefore:

1. **Raise confidence in semantics** with a reusable, independent instruction-test harness before making broad changes.
2. **Fix high-impact address and operand modelling**, especially program-bank wrapping and immediate constants.
3. **Treat dynamic CPU state as an analysis problem**, not a simple SLEIGH macro fix. Improve known-state propagation, and represent uncertainty honestly.
4. **Improve onboarding and workflow** with vector discovery, memory-map setup, and a documented supported-target profile.
5. **Measure decompiler quality separately** from disassembly quality, including the JSR/JSL and RTS/RTL stack conventions.

The repo owner should first decide whether the product target is a generic W65C816 language module or a SNES ROM reverse-engineering workflow. The CPU semantics can be shared, but loaders and memory maps are platform-specific and should usually be separate.

## Largest disadvantages and the resources needed

### 1. Semantic correctness is not yet demonstrated broadly

**Why this matters:** incorrect register flags, stack effects, widths, or addressing rules contaminate every later analysis result. A compiler-clean SLEIGH file only proves that the specification is accepted by Ghidra. The current test suite covers selected instruction sequences rather than systematically testing every opcode, addressing mode, width and relevant emulation/native state.

**Required work:** adapt the [SingleStepTests/65816](https://github.com/SingleStepTests/65816) JSON corpus to the existing Ghidra `PcodeEmulator` harness. Compare normalized initial/final register values and touched RAM, with explicit handling of context bits and instructions whose architectural behavior spans multiple bus cycles. Start with a small deterministic sample in pull-request CI; run a much broader set nightly or on demand. Turn every confirmed mismatch into a small regression case.

**Important caveat:** do not treat any single emulator or generated corpus as infallible. Cross-check surprising cases against the WDC documentation and at least one independent implementation. The corpus documentation says it provides per-instruction initial/final processor and memory state, while recent public experience reports show it can surface ambiguous or disputed cases. Record the source and rationale for every exception instead of silently excluding failures.

**Relevant files:** `src/test/java/ghidra65816/PcodeEmulatorRegressionTest.java`, `src/test/java/ghidra65816/NativeStatusPullRegressionTest.java`, `tests/test_sleigh_regressions.py`, `DEVELOPMENT.md`, `.github/workflows/sleigh.yml`, and `data/languages/all instructions.ods`.

### 2. Program-bank boundaries and instruction-byte modelling

**Why this matters:** the 65816's 16-bit PC increments inside a program bank while PBR identifies the bank. The README warns that instructions or operands crossing a program-bank boundary may be analysed incorrectly. The current PC-relative address helpers explicitly try to wrap within the current bank, but that does not by itself prove all instruction fetch, operand-byte, call, and pointer cases are correct.

**Required work:** create boundary fixtures around `$xx:FFFC` through `$xx:FFFF` for 1-, 2-, 3- and 4-byte instructions and their operand reads. Check next-PC values, PBR retention, branch targets, references and disassembly against the WDC rules. Distinguish *instruction-fetch wrapping* from *data pointer wrapping*: each addressing form has different bank/page rules. Repair the smallest common helper when the same bug class is shared.

**Relevant files:** `data/languages/658xx_memaccess_pc.sinc`, `data/languages/658xx_memaccess.sinc`, and the instruction constructors in `data/languages/658xx.sinc`.

### 3. M/X/E mode tracking is limited by the static-analysis model

**Why this matters:** `MF` and `XF` change instruction width and therefore can change where the next instruction's bytes end. `EF` changes emulation/native behavior. `PLP` and `RTI` restore status from the stack; `XCE` depends on Carry. At runtime these can be known, but a static disassembler cannot always infer an arbitrary stack byte or a Carry value at every control-flow join. SLEIGH context variables select decoding; they are not ordinary runtime registers.

**Required work:** build a focused context-analysis prototype that propagates facts only when justified—for example, values set by obvious `REP`/`SEP` instructions, a provably known Carry at `XCE`, or status bytes recovered from a known stack setup. When the state is unknown, retain an unknown/manual override path rather than pretending one decode is certain. Add fixtures for straight-line code, branches with conflicting states, calls, and unknown stack contents.

**Expected outcome:** reduce manual context setup for common code, not promise perfect automatic decoding for arbitrary programs. Fully general resolution of unknown runtime stack state is not a realistic guarantee of a static disassembler without additional assumptions or emulation-derived knowledge.

**Relevant files:** context declarations and `PLP`/`RTI`/`XCE` constructors in `data/languages/658xx.sinc`; [Ghidra SLEIGH context documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh_context.html); `tests/test_sleigh_regressions.py`.

### 4. Immediate operands are modelled as references, reducing value propagation

**Why this matters:** the README and development guide say immediate operands are modelled through references to instruction bytes, which can limit constant propagation. That can make decompiler output and analysis less useful even when the CPU result is otherwise correct.

**Required work:** test a minimal change to represent immediate data as a correctly sized scalar value in P-Code while retaining correct operand formatting and mode-dependent length. Exercise immediate loads, arithmetic, compares, truncation/extension, references, and instructions at bank boundaries. Compare the resulting decompiler output before and after. Do not globally replace address references until it is clear which constructors need a reference for encoding/formatting and which instruction semantics need an immediate value.

**Relevant files:** `RefImm8`, `RefImm16`, `RefImmMF`, `RefImmXF`, and consumers in `data/languages/658xx_memaccess.sinc` and `data/languages/658xx.sinc`.

### 5. Interrupt vectors and initial memory state require too much manual setup

**Why this matters:** `data/languages/65816.pspec` creates vector symbols, but its comment explains why Ghidra cannot simply treat the two-byte vector contents as a three-byte code pointer in this setup. Users must create entry points manually or rely on a loader/script. Raw binaries also need a correct bank/memory map and initial processor state.

**Required work:** add a small script or optional analyzer that reads each applicable two-byte vector target as a bank-zero address, creates a reference and entry point/function when appropriate, and applies sensible processor context. Keep platform assumptions outside the CPU core. If SNES is the main target, study a ROM loader that maps LoROM/HiROM banks, RAM/MMIO and mirrors rather than solving that inside SLEIGH.

**Relevant files:** `data/languages/65816.pspec`, `data/languages/65816.ldefs`, and installation/usage documentation. Useful precedent: [joshleaves/ghidra-snes](https://github.com/joshleaves/ghidra-snes), which documents SNES ROM mapping and vector labels.

### 6. Decompiler and calling-convention quality are not clearly measured

**Why this matters:** the original archived project describes decompilation as potentially unusable. The current `65816.cspec` has a minimal unknown-call prototype and a two-byte return-address varnode, while the language semantics show `JSL` pushes 24-bit return state and `RTL` pulls a 24-bit return state. This is a **high-priority validation lead, not a confirmed defect**: the exact effect on Ghidra's call/stack analysis should be tested before changing the specification.

**Required work:** add small decompiler fixtures for `JSR`/`RTS` and `JSL`/`RTL`, both native and emulation modes, and verify return-flow recovery, stack offsets, argument recovery where a convention is known, and function boundaries. Document unsupported or platform-specific calling conventions. Tune `65816.cspec` only after reproducing the actual decompiler problem.

**Relevant files:** `data/languages/65816.cspec`, `JSL`/`JSR`/`RTL`/`RTS` semantics in `data/languages/658xx.sinc`, plus Ghidra decompiler test examples in the Ghidra source repository.

### 7. 65802 support is a separate compatibility target

**Why this matters:** the language definition has a commented-out 65802 entry and the README says the variant is unsupported. Supporting another chip variant expands the test matrix and can complicate context rules.

**Required work:** make this a separate milestone only if there is a real user requirement. Define differences from the W65C816 in a reference matrix, then add its own language ID/specification and tests. Do not let optional 65802 support delay bank-boundary, context, and core-semantic work for the primary processor.

### 8. Reproducibility is good, but it is not a quality signal by itself

The existing workflow pins a Ghidra release/hash, compiles SLEIGH, checks repeatability and runs runtime tests. Keep that. Improve confidence by adding broader semantic comparisons, decompiler fixtures and a supported-version policy. Publish clear releases only when the test matrix and limitations are reviewed and accurately described.

## Proposed work order

| Priority | Work item | Acceptance evidence |
|---|---|---|
| P0 | Define target scope: generic 65816, SNES workflow, or both as separate layers | One-page scope and support matrix |
| P0 | Build the SingleStepTests adapter and add a small CI sample | State/memory comparison is reproducible; mismatches are reported with opcode, mode and input |
| P0 | Add targeted program-bank boundary tests | Fetch, operand, branch and return cases pass known reference cases |
| P1 | Extend tests across addressing modes, M/X/E states, flags and stack operations | Published opcode/mode/state coverage summary; failures become regression tests |
| P1 | Add decompiler fixtures for immediate values and near/far calls | Stable before/after output and explicit call/return/stack assertions |
| P1 | Prototype cautious automatic context propagation | Known-state paths improve without forcing a wrong decode at ambiguous joins |
| P2 | Add vector/entry-point helper or optional analyzer | Correct bank-zero targets and repeatable behavior on fixture programs |
| P2 | Add SNES loader integration if SNES is in scope | LoROM/HiROM fixture images map to expected addresses and vectors |
| P3 | Add 65802 support if user demand justifies it | Separate compatibility matrix and passing variant-specific tests |
| P3 | Release, support matrix and troubleshooting guide | Versioned extension, clear known limitations, repeatable installation |

KISS rule: each row should be a small PR with a test that fails before the fix. Do not combine a semantic fix, loader work and documentation restructuring in one PR.

## Resource ranking: most useful to least useful

Scores estimate how directly each resource can remove the current limitations, not the quality of the project itself.

| Rank | Resource | Usefulness | Best use | Cautions |
|---:|---|---:|---|---|
| 1 | [SingleStepTests/65816](https://github.com/SingleStepTests/65816) | 10/10 | Broad initial/final processor state and RAM tests; turn representative cases into regressions and grow toward broad per-opcode coverage | Large; build a filtered adapter instead of making every PR download/run the entire corpus. Investigate disagreements rather than blindly accepting every case |
| 2 | [Official WDC W65C816S datasheet](https://www.westerndesigncenter.com/wdc/documentation/w65c816s.pdf) and [Programming the 65816 reference](https://wiki.superfamicom.org/65816-reference) | 9.5/10 | Authoritative register, mode, address, stack, interrupt and instruction rules; resolve contradictory emulator/test results | The datasheet and programming reference have different detail; record which rule supports each test |
| 3 | [MAME 65816 implementation](https://github.com/mamedev/mame/tree/master/src/devices/cpu/g65816) | 9/10 | Independent implementation to compare arithmetic flags, stack effects, wrapping and status semantics | An emulator is a cross-check, not the specification; check comments/TODOs and version history |
| 4 | [Ghidra SLEIGH context manual](https://ghidra.re/ghidra_docs/languages/html/sleigh_context.html), [SLEIGH manual](https://ghidra.re/ghidra_docs/languages/html/sleigh.html), and [constructors/global context documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh_constructors.html) | 9/10 | Understand decode-time context, `globalset`, instruction patterns, operand construction and the limits of static mode tracking | Read docs that match the Ghidra version pinned in CI before depending on version-specific behavior |
| 5 | [Ghidra 12.1 `PcodeEmulator` API](https://www.ghidradocs.com/12.1_PUBLIC/docs/GhidraAPI_javadoc/api/ghidra/pcode/emu/PcodeEmulator.html) | 8.8/10 | Extend the existing runtime harness using Ghidra's concrete P-Code execution engine | It validates P-Code execution, not cycle-accurate hardware timing or whole-program analysis |
| 6 | [joshleaves/ghidra-snes](https://github.com/joshleaves/ghidra-snes) | 8.5/10 for SNES; 5/10 generic | Reuse ideas for LoROM/HiROM mapping, SNES RAM/MMIO, mirror banks, loader integration and vector labels | Platform-specific and derived from prior 65816 work. Compare code and license, and port the smallest needed idea rather than copying wholesale |
| 7 | [Ghidra source: 6502 processor](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors/6502) and [developer guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md) | 8/10 | Learn existing processor-module structure, extension APIs, data types, analyzers and test patterns; use the user-provided [Ghidra fork](https://github.com/kaayzouee/ghidra) for browsing if convenient | Use the exact version/tag matching CI to avoid copying APIs or examples that drifted in newer source |
| 8 | [Original archived processor module](https://github.com/achan1989/ghidra-65816) | 7.5/10 | History, design intent, legacy limitations and license/attribution context | Explicitly archived/unmaintained and warns that the implementation is early; treat it as history, not authority |
| 9 | [65816 test-ROM discussion and suite pointer](https://forums.nesdev.org/viewtopic.php?t=24940) | 7/10 | End-to-end execution fixtures covering many instructions, addressing modes and widths | ROM tests can be harder to triage than single-instruction cases and do not cover every timing or hardware integration behavior |
| 10 | [REA](https://github.com/morluto/rea) / [REA website](https://rea.tools/) | 4.5/10 | Speed up repository exploration and repeatable reverse-engineering workflows after core tests exist | It is a workflow/tooling aid, not an independent processor-correctness oracle |
| 11 | [update-ghidra-version packaging](https://github.com/kaayzouee/update-ghidra-version/tree/master/pkgs/tools/security/ghidra) | 3.5/10 | Reproducible Ghidra packaging, pinning, patches and extension distribution | Little direct value for CPU semantics or analysis correctness; revisit when release/install support is a priority |

## Website/repository research notes

- The [current repository README](https://github.com/kaayzouee/ghidra-65816/blob/master/README.md) identifies the module as an experimental community continuation, not a cycle-accurate emulator, and explicitly lists key limitations.
- [`DEVELOPMENT.md`](https://github.com/kaayzouee/ghidra-65816/blob/master/DEVELOPMENT.md) documents the SLEIGH compilation, deterministic output check, Python tests and P-Code runtime suite. It already sets the right principle: successful compilation is not proof of hardware correctness.
- The prior PR history contains useful lessons. [PR #4](https://github.com/kaayzouee/ghidra-65816/pull/4) was closed after decimal ADC/SBC behavior was checked against the WDC manual and MAME. [PR #5](https://github.com/kaayzouee/ghidra-65816/pull/5) was closed because changing runtime stack bits into static context had not been justified. [PR #6](https://github.com/kaayzouee/ghidra-65816/pull/6) was closed after a direct-page wrapping assumption was contradicted by reference implementation evidence. This is a strong argument for an independent validation harness before broad semantic edits.
- The [SingleStepTests/65816 README](https://github.com/SingleStepTests/65816) describes state-before/state-after test cases, including memory and bus activity. A recent [independent public test report](https://x65.zone/news/2026/08/26/65816-single-step-tests.html) describes the practical value of the corpus and also notes disputed edge cases, reinforcing the need for triangulation.
- Ghidra's [SLEIGH context documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh_context.html) describes context as state used by disassembly. Its [constructors documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh_constructors.html) explains `globalset` and why permanent context changes are suggestions to the analysis engine. This explains why runtime-dependent mode tracking is not automatically solved by changing P-Code alone.

## Recommended first three PRs

1. **Regression harness PR:** add a minimal adapter for selected SingleStepTests cases and report the exact input/state on mismatch. Keep the normal CI sample bounded.
2. **Bank-boundary PR:** add failing fixtures first, fix only the common address helper(s) proven wrong, then check near/far calls and branches.
3. **Immediate/decompiler PR:** create a small decompiler fixture showing the current constant-propagation failure, change scalar modelling for a narrow set of immediate instructions, and compare output.

Keep context propagation, vector discovery, SNES loader integration and 65802 support as separate follow-up PRs. This sequence improves correctness evidence and real user confidence without mixing too many concerns.

## Sources

- [Ghidra-65816 repository](https://github.com/kaayzouee/ghidra-65816)
- [WDC W65C816S datasheet (PDF)](https://www.westerndesigncenter.com/wdc/documentation/w65c816s.pdf)
- [SingleStepTests/65816](https://github.com/SingleStepTests/65816)
- [MAME 65816 source](https://github.com/mamedev/mame/tree/master/src/devices/cpu/g65816)
- [Ghidra language specification docs](https://ghidra.re/ghidra_docs/languages/index.html)
- [Ghidra 12.1 PcodeEmulator API](https://www.ghidradocs.com/12.1_PUBLIC/docs/GhidraAPI_javadoc/api/ghidra/pcode/emu/PcodeEmulator.html)
- [SNES Ghidra extension](https://github.com/joshleaves/ghidra-snes)
- [Archived original module](https://github.com/achan1989/ghidra-65816)
- [User-provided Ghidra source fork](https://github.com/kaayzouee/ghidra)
- [User-provided Ghidra packaging repository](https://github.com/kaayzouee/update-ghidra-version)
- [REA repository](https://github.com/morluto/rea) and [website](https://rea.tools/)
