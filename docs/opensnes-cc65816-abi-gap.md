# OpenSNES cc65816 ABI: model gap and candidate design

**Updated:** 2026-10-28 · Research for P3 in [the scope work roadmap](pr28-scope-work-roadmap.md).

## Public ABI facts

OpenSNES publishes the [cc65816 ABI reference](https://github.com/k0b3n4irb/opensnes/blob/main/compiler/ABI.md), and the checked-in assembly snapshot records its provenance in [the fixture](../tests/fixtures/abi/opensnes-cc65816-reference.asm). Its examples are documented as actual compiler output.

Relevant properties:

- Arguments are pushed **left-to-right**. Therefore, the rightmost/last argument is closest to the incoming stack pointer; the first declared argument is at the highest stack offset.
- JSL/RTL gives a three-byte return address. The first stack argument begins at SP + framesize + 4.
- u8 and u16 use two-byte argument slots. u32, s32, and pointers use four-byte slots.
- Returns through 16 bits use the 16-bit accumulator. For 32-bit values and pointers, the low 16 bits use the accumulator and the high 16 bits use the compiler's direct-page global tcc__retval_hi.
- The caller removes argument bytes after the call. The ABI also has no callee-saved general registers and assumes the compiler's documented DP/DBR environment.

The current optional __near and __far prototypes in 65816.cspec intentionally use a register-only C/X/Y input model. They must not be selected for a function compiled with the OpenSNES stack ABI.

## Why an active compiler prototype is deferred

Ghidra's [standard prototype strategy](https://lemuellew.github.io/Ghidra-Compiler-Specification-Document/cspec_parampass.html) allocates parameters by walking its ordered pentry resource list. A plain stack pentry at offset 4 assigns the first formal parameter the lowest stack slot; that is opposite the OpenSNES source-order layout. The reversejustify behavior for stack pointers is about padding/justification, not reversing all formal parameters.

There is an upstream Ghidra proposal, [PR #9921](https://github.com/NationalSecurityAgency/ghidra/pull/9921), for an input stackltr="true" attribute that mirrors assigned stack parameter locations and reverses recovered stack trials. As of this update, that PR is open, not merged. The repository pins Ghidra 12.1.4; adding stackltr to the active compiler spec now would risk an unsupported or silently ignored attribute and incorrect decompilation.

There is a second limitation: the compiler's 32-bit result is split between the accumulator and tcc__retval_hi, rather than a normal contiguous return varnode. Even with left-to-right stack argument allocation available, a full compiler ABI model needs an independent decision for 32-bit and pointer returns.

## Candidate model after upstream support is available

This fragment is a design sketch for functions whose return values fit in the 16-bit accumulator. It is **not enabled in 65816.ldefs or 65816.cspec** and must not be used with the current pinned Ghidra release.

~~~xml
<prototype name="__opensnes_cc65816_16ret"
           extrapop="3" stackshift="3" strategy="standard">
  <input stackltr="true">
    <pentry minsize="1" maxsize="500" align="2">
      <addr space="stack" offset="4"/>
    </pentry>
  </input>
  <output>
    <pentry minsize="1" maxsize="2">
      <register name="C"/>
    </pentry>
  </output>
  <returnaddress>
    <varnode space="stack" offset="1" size="3"/>
  </returnaddress>
</prototype>
~~~

Before enabling even this bounded model, validate it in a Ghidra build that supports stackltr with headless decompiler checks for: two parameters of equal size, arguments of mixed 2- and 4-byte slot sizes, a function with one argument, JSL/RTL stack effects, and caller cleanup. Keep 32-bit/pointer return support separate until tcc__retval_hi is represented correctly.

## Exit conditions

1. Ghidra upstream implements and ships stackltr in a supported release, or the project deliberately maintains a patched build.
2. The above stack-argument model passes runtime/decompiler validation against compiler-generated examples.
3. The 32-bit/pointer return mechanism is separately modelled or explicitly declared out of scope for the compiler-specific prototype.
