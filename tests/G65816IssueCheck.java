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