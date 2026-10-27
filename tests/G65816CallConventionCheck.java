import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class G65816CallConventionCheck extends GhidraScript {
    private RegisterValue initialContext() {
        Register context = currentProgram.getLanguage().getContextBaseRegister();
        RegisterValue value = new RegisterValue(context);
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_MF"), BigInteger.ONE);
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_XF"), BigInteger.ONE);
        // Native mode with 8-bit accumulator and index registers.
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_EF"), BigInteger.ZERO);
        return value;
    }

    private RegisterValue initialContext16() {
        Register context = currentProgram.getLanguage().getContextBaseRegister();
        RegisterValue value = new RegisterValue(context);
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_MF"), BigInteger.ZERO);
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_XF"), BigInteger.ZERO);
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_EF"), BigInteger.ZERO);
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

    private void setRegisterAbi(Function function, String convention) throws Exception {
        function.setCallingConvention(convention);
        function.setReturnType(UnsignedCharDataType.dataType, SourceType.USER_DEFINED);
        function.updateFunction(
            convention,
            null,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true,
            SourceType.USER_DEFINED,
            new ParameterImpl("argC", UnsignedCharDataType.dataType, currentProgram),
            new ParameterImpl("argX", UnsignedCharDataType.dataType, currentProgram),
            new ParameterImpl("argY", UnsignedCharDataType.dataType, currentProgram));
    }

    private void setRegisterAbi16(Function function, String convention) throws Exception {
        function.setCallingConvention(convention);
        function.setReturnType(UnsignedShortDataType.dataType, SourceType.USER_DEFINED);
        function.updateFunction(
            convention,
            null,
            FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true,
            SourceType.USER_DEFINED,
            new ParameterImpl("argC", UnsignedShortDataType.dataType, currentProgram),
            new ParameterImpl("argX", UnsignedShortDataType.dataType, currentProgram),
            new ParameterImpl("argY", UnsignedShortDataType.dataType, currentProgram));
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        try (PrintStream out = new PrintStream(args[0])) {
            RegisterValue context = initialContext();
            Address callerAddress = toAddr(0x8000);
            Address nearAddress = toAddr(0x8100);
            Address farAddress = toAddr(0x8200);
            Address caller16Address = toAddr(0x8020);
            Address near16Address = toAddr(0x8300);
            Address far16Address = toAddr(0x8400);

            disassembleAt(callerAddress, context);
            disassembleAt(nearAddress, context);
            disassembleAt(farAddress, context);
            RegisterValue context16 = initialContext16();
            // Establish the callees' 16-bit accumulator/index context before
            // disassembling the caller that reaches them.
            disassembleAt(near16Address, context16);
            disassembleAt(far16Address, context16);
            disassembleAt(caller16Address, context);

            Function caller = functionAtOrCreate(callerAddress, "caller");
            Function near = functionAtOrCreate(nearAddress, "near_fn");
            Function far = functionAtOrCreate(farAddress, "far_fn");
            Function caller16 = functionAtOrCreate(caller16Address, "caller16");
            Function near16 = functionAtOrCreate(near16Address, "near16_fn");
            Function far16 = functionAtOrCreate(far16Address, "far16_fn");

            setRegisterAbi(near, "__near");
            setRegisterAbi(far, "__far");
            setRegisterAbi16(near16, "__near");
            setRegisterAbi16(far16, "__far");
            caller.setCallingConvention("__unknowncall");
            caller.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            caller16.setCallingConvention("__unknowncall");
            caller16.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);

            out.println("near=" + near.getCallingConventionName());
            out.println("far=" + far.getCallingConventionName());
            out.println("near16=" + near16.getCallingConventionName());
            out.println("far16=" + far16.getCallingConventionName());

            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) {
                    throw new IllegalStateException("Decompiler could not open program");
                }
                decompileAndPrint(decompiler, caller, "caller", out);
                decompileAndPrint(decompiler, near, "near", out);
                decompileAndPrint(decompiler, far, "far", out);
                decompileAndPrint(decompiler, caller16, "caller16", out);
                decompileAndPrint(decompiler, near16, "near16", out);
                decompileAndPrint(decompiler, far16, "far16", out);
            }
            finally {
                decompiler.dispose();
            }
        }
    }

    private void decompileAndPrint(
            DecompInterface decompiler, Function function, String label, PrintStream out)
            throws Exception {
        DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
        if (!result.decompileCompleted()) {
            throw new IllegalStateException(
                function.getName() + " decompilation failed: " + result.getErrorMessage());
        }
        out.println("=== " + label + " decompile ===");
        out.println(result.getDecompiledFunction().getC());
    }
}
