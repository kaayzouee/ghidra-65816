// Repair bank-local fall-through when all instruction bytes remain in the same 65816 bank.
// This script does not repair instructions whose bytes straddle $xx:FFFF.
// @category 65816

import java.io.PrintStream;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;

public class Repair65816BankFallthrough extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String language = currentProgram.getLanguage().getLanguageID().getIdAsString();
        if (!language.startsWith("65816:")) {
            throw new IllegalArgumentException("Expected a 65816 program, got " + language);
        }

        String[] args = getScriptArgs();
        if (args.length > 1) {
            throw new IllegalArgumentException("Optional argument: report output path");
        }

        AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        PrintStream report = args.length == 1 ? new PrintStream(args[0], "UTF-8") : null;
        int repaired = 0;
        int unsafe = 0;
        int preserved = 0;
        int transaction = currentProgram.startTransaction("Repair 65816 bank-local fall-through");
        boolean commit = false;
        try {
            for (Instruction instruction : currentProgram.getListing().getInstructions(true)) {
                monitor.checkCancelled();
                Address address = instruction.getAddress();
                if (!address.getAddressSpace().equals(defaultSpace)) {
                    continue; // Never guess how overlays map to the 24-bit CPU bus.
                }

                long offset = address.getOffset();
                int length = instruction.getLength();
                if (length < 1 || (offset & ~0xffffffL) != 0) {
                    continue;
                }

                long endPc = (offset & 0xffffL) + length;
                if (endPc > 0x10000L) {
                    unsafe++;
                    if (report != null) {
                        report.printf("case=unsafe|entry=%06x|length=%d%n", offset, length);
                    }
                    continue; // The instruction itself used non-wrapped bytes; never patch only its edge.
                }
                if (endPc != 0x10000L || !instruction.getFlowType().hasFallthrough()) {
                    continue;
                }
                if (instruction.getDefaultFallThroughOffset() != length ||
                        instruction.isFallThroughOverridden()) {
                    preserved++;
                    continue; // Respect nonstandard flow and explicit user overrides.
                }

                Address correct = defaultSpace.getAddress(offset & 0xff0000L);
                if (correct.equals(instruction.getFallThrough())) {
                    continue; // Already correct, e.g. after a future Ghidra core fix.
                }

                instruction.setFallThrough(correct);
                if (!correct.equals(instruction.getFallThrough())) {
                    throw new AssertionError("Failed to set fall-through for " + address);
                }
                repaired++;
                if (report != null) {
                    report.printf(
                        "case=repair|entry=%06x|length=%d|fallthrough=%06x%n",
                        offset, length, instruction.getFallThrough().getOffset());
                }
            }
            commit = true;
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
            if (report != null) {
                report.printf(
                    "case=summary|repaired=%d|unsafe=%d|preserved=%d%n",
                    repaired, unsafe, preserved);
                report.close();
            }
        }

        println("65816 fall-through: repaired=" + repaired +
            ", unsafe straddling instructions=" + unsafe +
            ", preserved custom flow/overrides=" + preserved +
            ". This does not fix wrapped instruction-byte fetch.");
    }
}
