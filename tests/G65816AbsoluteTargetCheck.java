import java.io.PrintStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;

public class G65816AbsoluteTargetCheck extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected output path and code base address");
        }

        long codeBase = Long.parseLong(args[1], 16);
        var language = currentProgram.getLanguage();
        Register context = language.getContextBaseRegister();
        RegisterValue initialContext = new RegisterValue(context);
        for (String name : new String[] { "ctx_EF", "ctx_MF", "ctx_XF" }) {
            initialContext = initialContext.assign(
                language.getRegister(name), BigInteger.ZERO);
        }

        long[] offsets = { 0, 3, 6, 10 };
        String[] mnemonics = { "JMP", "JSR", "JML", "JSL" };
        long[] targets = { 0x121234, 0x125678, 0x345678, 0x789abc };

        try (PrintStream out = new PrintStream(args[0])) {
            for (int i = 0; i < offsets.length; i++) {
                Address address = toAddr(codeBase + offsets[i]);
                DisassembleCommand command = new DisassembleCommand(address, null, false);
                command.setInitialContext(initialContext);
                if (!command.applyTo(currentProgram, monitor)) {
                    throw new IllegalStateException(
                        "Disassembly failed at " + address + ": " + command.getStatusMsg());
                }

                Instruction instruction = currentProgram.getListing().getInstructionAt(address);
                if (instruction == null) {
                    throw new AssertionError("No instruction at " + address);
                }
                if (!mnemonics[i].equals(instruction.getMnemonicString())) {
                    throw new AssertionError("Expected " + mnemonics[i] + " at " + address
                        + ", got " + instruction.getMnemonicString());
                }

                String operand = instruction.getDefaultOperandRepresentation(0);
                String normalizedOperand = operand
                    .replaceAll("(?i)0x", "")
                    .replaceAll("[^0-9a-fA-F]", "")
                    .toLowerCase(Locale.ROOT);
                String expectedHex = String.format("%06x", targets[i]);
                if (!normalizedOperand.contains(expectedHex)) {
                    throw new AssertionError("Expected full target " + expectedHex + " in operand '"
                        + operand + "' at " + address);
                }

                Address target = toAddr(targets[i]);
                boolean defaultFlowMatches = Arrays.stream(instruction.getDefaultFlows())
                    .anyMatch(target::equals);
                if (!defaultFlowMatches) {
                    throw new AssertionError("Expected flow target " + target + " from " + address
                        + ", got " + Arrays.toString(instruction.getDefaultFlows()));
                }

                boolean flowReferenceMatches = Arrays.stream(instruction.getReferencesFrom())
                    .anyMatch(reference -> target.equals(reference.getToAddress())
                        && reference.getReferenceType().isFlow());
                if (!flowReferenceMatches) {
                    throw new AssertionError("No flow reference to " + target + " from " + address
                        + "; references: " + Arrays.toString(instruction.getReferencesFrom()));
                }

                out.printf("%06x|%s|%s|%06x%n", address.getOffset(),
                    instruction.getMnemonicString(), operand, target.getOffset());
            }

            // Indirect forms must stay computed even when their pointer bytes are visible.
            long[] indirectOffsets = { 14, 17, 20, 23 };
            String[] indirectMnemonics = { "JMP", "JMP", "JML", "JSR" };
            for (int i = 0; i < indirectOffsets.length; i++) {
                Address address = toAddr(codeBase + indirectOffsets[i]);
                DisassembleCommand command = new DisassembleCommand(address, null, false);
                command.setInitialContext(initialContext);
                if (!command.applyTo(currentProgram, monitor)) {
                    throw new IllegalStateException(
                        "Disassembly failed at " + address + ": " + command.getStatusMsg());
                }

                Instruction instruction = currentProgram.getListing().getInstructionAt(address);
                if (instruction == null
                        || !indirectMnemonics[i].equals(instruction.getMnemonicString())) {
                    throw new AssertionError("Expected " + indirectMnemonics[i]
                        + " indirect form at " + address + ", got " + instruction);
                }

                var flowType = instruction.getFlowType();
                boolean expectedCall = "JSR".equals(indirectMnemonics[i]);
                if (!flowType.isComputed()
                        || flowType.isCall() != expectedCall
                        || flowType.isJump() == expectedCall) {
                    throw new AssertionError("Expected computed "
                        + (expectedCall ? "call" : "jump") + " at " + address
                        + ", got " + flowType);
                }
            }
        }
    }
}
