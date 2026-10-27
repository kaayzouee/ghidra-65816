import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class G65816CallConventionCheck extends GhidraScript {
    private RegisterValue initialContext() {
        Register context = currentProgram.getLanguage().getContextBaseRegister();
        RegisterValue value = new RegisterValue(context);
        for (String name : new String[] { "ctx_MF", "ctx_XF", "ctx_EF" }) {
            value = value.assign(currentProgram.getLanguage().getRegister(name), BigInteger.ONE);
        }
        return value;
    }

    private void disassembleAt(Address address, RegisterValue context) throws Exception {
        if (currentProgram.getListing().getInstructionAt(address) != null) {
            return;
        }
        DisassembleCommand command = new DisassembleCommand(address, null, true);
        command.setInitialContext(context);
        if (!command.applyTo(currentProgram, monitor)) {
            throw new IllegalStateException(
                "Disassembly failed at " + address + ": " + command.getStatusMsg());
        }
    }

    private Function functionAtOrCreate(Address address, String name) throws Exception {
        Function function = getFunctionAt(address);
        if (function == null) {
            function = createFunction(address, name);
        }
        if (function == null) {
            throw new IllegalStateException("Could not create function " + name + " at " + address);
        }
        return function;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        try (PrintStream out = new PrintStream(args[0])) {
            RegisterValue context = initialContext();
            Address callerAddress = toAddr(0x8000);
            Address nearAddress = toAddr(0x8100);
            Address farAddress = toAddr(0x8200);

            disassembleAt(callerAddress, context);
            disassembleAt(nearAddress, context);
            disassembleAt(farAddress, context);

            Function caller = functionAtOrCreate(callerAddress, "caller");
            Function near = functionAtOrCreate(nearAddress, "near_fn");
            Function far = functionAtOrCreate(farAddress, "far_fn");

            near.setCallingConvention("__near");
            near.setReturnType(UnsignedCharDataType.dataType, SourceType.USER_DEFINED);
            far.setCallingConvention("__far");
            far.setReturnType(UnsignedCharDataType.dataType, SourceType.USER_DEFINED);
            caller.setCallingConvention("__unknowncall");
            caller.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);

            out.println("near=" + near.getCallingConventionName());
            out.println("far=" + far.getCallingConventionName());

            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) {
                    throw new IllegalStateException("Decompiler could not open program");
                }
                DecompileResults result = decompiler.decompileFunction(caller, 30, monitor);
                if (!result.decompileCompleted()) {
                    throw new IllegalStateException(
                        "Caller decompilation failed: " + result.getErrorMessage());
                }
                out.println("=== caller decompile ===");
                out.println(result.getDecompiledFunction().getC());
            }
            finally {
                decompiler.dispose();
            }
        }
    }
}
