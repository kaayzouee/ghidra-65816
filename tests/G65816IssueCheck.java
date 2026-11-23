import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class G65816IssueCheck extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        try (PrintStream out = new PrintStream(args[0])) {
            var lang = currentProgram.getLanguage();
            Register context = lang.getContextBaseRegister();
            RegisterValue value = new RegisterValue(context);
            for (String name : new String[] { "ctx_MF", "ctx_XF", "ctx_EF" }) {
                value = value.assign(lang.getRegister(name), BigInteger.ONE);
            }

            Address entry = toAddr(Long.parseLong(args[1], 16));
            DisassembleCommand command = new DisassembleCommand(entry, null, true);
            command.setInitialContext(value);
            if (!command.applyTo(currentProgram, monitor)) {
                throw new IllegalStateException("Disassembly failed: " + command.getStatusMsg());
            }
            RegisterValue subroutineContext = value;
            for (String name : new String[] { "ctx_MF", "ctx_XF", "ctx_EF" }) {
                subroutineContext = subroutineContext.assign(lang.getRegister(name), BigInteger.ZERO);
            }
            Address decompileAddress = toAddr(Long.parseLong(args[2], 16));
            if (currentProgram.getListing().getInstructionAt(decompileAddress) == null) {
                DisassembleCommand subroutineCommand =
                        new DisassembleCommand(decompileAddress, null, true);
                subroutineCommand.setInitialContext(subroutineContext);
                if (!subroutineCommand.applyTo(currentProgram, monitor)) {
                    throw new IllegalStateException(
                            "Subroutine disassembly failed: " + subroutineCommand.getStatusMsg());
                }
            }
            long[] xceStarts = {0x8100, 0x8110, 0x8120, 0x8130, 0x8140, 0x8150};
            int[] xceModes = {0, 1, 0, 1, 0, 1};
            int[] ldaOffsets = {4, 4, 4, 4, 5, 5};
            int[] ldaLengths = {2, 2, 3, 3, 2, 3};
            for (int i = 0; i < xceStarts.length; i++) {
                RegisterValue initial = new RegisterValue(context);
                for (String name : new String[] { "ctx_MF", "ctx_XF", "ctx_EF" }) {
                    initial = initial.assign(lang.getRegister(name),
                        BigInteger.valueOf(xceModes[i]));
                }
                Address start = toAddr(xceStarts[i]);
                DisassembleCommand xceCommand = new DisassembleCommand(start, null, true);
                xceCommand.setInitialContext(initial);
                if (!xceCommand.applyTo(currentProgram, monitor)) {
                    throw new AssertionError("XCE sequence did not disassemble at " + start);
                }
                Address ldaAddress = toAddr(xceStarts[i] + ldaOffsets[i]);
                Instruction lda = currentProgram.getListing().getInstructionAt(ldaAddress);
                if (lda == null || !"LDA".equals(lda.getMnemonicString())
                        || lda.getLength() != ldaLengths[i]) {
                    throw new AssertionError("Wrong decode after XCE at " + ldaAddress
                        + ": expected LDA/" + ldaLengths[i] + ", got " + lda);
                }
            }

            for (int i = 0; i < 2; i++) {
                long startOffset = 0x8160 + i * 0x10;
                RegisterValue initial = new RegisterValue(context);
                for (String name : new String[] { "ctx_MF", "ctx_XF", "ctx_EF" }) {
                    initial = initial.assign(lang.getRegister(name), BigInteger.ZERO);
                }
                DisassembleCommand branchCommand = new DisassembleCommand(
                    toAddr(startOffset), null, true);
                branchCommand.setInitialContext(initial);
                if (!branchCommand.applyTo(currentProgram, monitor)) {
                    throw new AssertionError("XCE branch disassembly failed at " + startOffset);
                }
                Instruction branch = currentProgram.getListing().getInstructionAt(
                    toAddr(startOffset + 1));
                String expectedBranch = i == 0 ? "BRA" : "BNE";
                if (branch == null || !expectedBranch.equals(branch.getMnemonicString())) {
                    throw new AssertionError("Expected " + expectedBranch + " at "
                        + toAddr(startOffset + 1));
                }
                Instruction sec = currentProgram.getListing().getInstructionAt(
                    toAddr(startOffset + 3));
                if (i == 0 && sec != null) {
                    throw new AssertionError("Unreachable SEC was disassembled");
                }
                if (i == 1 && (sec == null || !"SEC".equals(sec.getMnemonicString()))) {
                    throw new AssertionError("Conditional fallthrough did not reach SEC");
                }
                Instruction xce = currentProgram.getListing().getInstructionAt(
                    toAddr(startOffset + 4));
                Instruction lda = currentProgram.getListing().getInstructionAt(
                    toAddr(startOffset + 7));
                if (xce == null || !"XCE".equals(xce.getMnemonicString())
                        || lda == null || !"LDA".equals(lda.getMnemonicString())) {
                    throw new AssertionError("XCE or following LDA missing after branch");
                }
                if (i == 0 && lda.getLength() != 3) {
                    throw new AssertionError("BRA bypass should decode native LDA/3, got "
                        + lda.getLength());
                }
                if (i == 1) {
                    out.printf("XCE_BRANCH|%d%n", lda.getLength());
                }
            }

            createFunction(entry, "reset");
            Function function = getFunctionAt(decompileAddress);
            if (function == null) {
                function = createFunction(decompileAddress, null);
            }
            analyzeAll(currentProgram);

            for (Instruction instruction : currentProgram.getListing().getInstructions(true)) {
                int selfReferences = 0;
                for (Reference reference : instruction.getReferencesFrom()) {
                    Address target = reference.getToAddress();
                    if (target.isMemoryAddress()
                            && target.compareTo(instruction.getMinAddress()) >= 0
                            && target.compareTo(instruction.getMaxAddress()) <= 0) {
                        selfReferences++;
                    }
                }
                out.printf("%06x|%d|%d|%s%n", instruction.getAddress().getOffset(),
                        selfReferences, instruction.getLength(), instruction.getMnemonicString());
            }

            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                out.println("=== decompile");
                out.println(result.decompileCompleted()
                        ? result.getDecompiledFunction().getC()
                        : "FAILED " + result.getErrorMessage());
            } finally {
                decompiler.dispose();
            }
        }
    }
}