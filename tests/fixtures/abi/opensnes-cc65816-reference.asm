; OpenSNES cc65816 ABI reference snapshot (not a standalone object).
;
; Provenance:
;   Upstream: https://github.com/k0b3n4irb/opensnes/blob/main/compiler/ABI.md
;   ABI.md content blob SHA: 5156bcc0ff807c298aa5ecd2bff20796cb8a60dc
;   That document states that its assembly examples are actual output from
;   bin/cc65816 input.c -o output.asm. The matching compiler/PINS.md records:
;     cproc  075fa2cb03f026af20e403bce58d336cb1556d09
;     QBE    40839d81eeee52c7661d742f6da53261cc0b187f
;     WLA-DX 7382e4c8aff6b3e1a00459d9461cc487c5f55030
;   This repo checks the published assembly snapshot; it does not rebuild that
;   external compiler in CI.
;
; Example 1: generated leaf function
;   unsigned short sub(unsigned short a, unsigned short b) { return a - b; }
; The function reads stack-passed parameters, returns in A, and uses RTL.
sub:
    rep #$20
    lda 6,s
    sec
    sbc 4,s
    rtl

; Example 2: generated caller for
;   oamSet(0, 100, 50, 0x100, 0, 3, 0x40);
; The actual output pushes arguments to the stack, calls with JSL, and cleans
; the arguments in the caller. This is deliberately different from the
; register-only __near/__far examples in this repository.
    pea.w 0
    pea.w 100
    pea.w 50
    pea.w 256
    pea.w 0
    pea.w 3
    pea.w 64
    jsl oamSet
    tsa
    clc
    adc.w #14
    tas
