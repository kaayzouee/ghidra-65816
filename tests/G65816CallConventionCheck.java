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

    private RegisterValue initialContextEmulation() {
        Register context = currentProgram.getLanguage().getContextBaseRegister();
        RegisterValue value = new RegisterValue(context);
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_MF"), BigInteger.ONE);
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_XF"), BigInteger.ONE);
        // Emulation mode forces 8-bit accumulator/index registers and uses page-one stack.
        value = value.assign(currentProgram.getLanguage().getRegister("ctx_EF"), BigInteger.ONE);
        return value;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        try (PrintStream out = new PrintStream(args[0])) {
            RegisterValue context = initialContext();
            Address callerAddress = toAddr(0x808000);
            Address nearAddress = toAddr(0x808100);
            Address farAddress = toAddr(0x808200);
            Address caller16Address = toAddr(0x808020);
            Address near16Address = toAddr(0x808300);
            Address far16Address = toAddr(0x808400);
            Address callerVoidAddress = toAddr(0x808060);
            Address nearVoidAddress = toAddr(0x808500);
            Address farVoidAddress = toAddr(0x808600);
            Address emulationCallerAddress = toAddr(0x808700);
            Address nearEmulationAddress = toAddr(0x808800);
            Address farEmulationAddress = toAddr(0x808900);
            Address nestedCallerAddress = toAddr(0x8080A0);
            Address wrapperAddress = toAddr(0x808A00);
            Address stackDataCallerAddress = toAddr(0x808B00);
            Address registerEffectsCallerAddress = toAddr(0x808C00);
            Address registerEffectsCalleeAddress = toAddr(0x808C80);

            disassembleAt(callerAddress, context);
            disassembleAt(nearAddress, context);
            disassembleAt(farAddress, context);
            RegisterValue context16 = initialContext16();
            // Establish the callees' 16-bit accumulator/index context before
            // disassembling the caller that reaches them.
            disassembleAt(near16Address, context16);
            disassembleAt(far16Address, context16);
            disassembleAt(caller16Address, context);
            disassembleAt(nearVoidAddress, context);
            disassembleAt(farVoidAddress, context);
            disassembleAt(callerVoidAddress, context);
            // A wrapper makes a near call and a far call before returning to a
            // caller that then makes another near call. This tests that nested
            // calls restore the caller's stack baseline.
            disassembleAt(nestedCallerAddress, context);
            disassembleAt(wrapperAddress, context);
            // PHA data must survive a near/far call and be restored by PLA,
            // without being interpreted as a stack-passed argument.
            disassembleAt(stackDataCallerAddress, context);
            // The far void callee modifies DP, DBR, and status flags. Its caller
            // observes those effects through direct-page/absolute stores and BNE.
            disassembleAt(registerEffectsCalleeAddress, context);
            disassembleAt(registerEffectsCallerAddress, context);

            // In emulation mode M/X are 8-bit and the stack is page one. Set
            // callee context first so the caller cannot silently supply native mode.
            RegisterValue emulationContext = initialContextEmulation();
            disassembleAt(nearEmulationAddress, emulationContext);
            disassembleAt(farEmulationAddress, emulationContext);
            disassembleAt(emulationCallerAddress, emulationContext);

            Function caller = functionAtOrCreate(callerAddress, "caller");
            Function near = functionAtOrCreate(nearAddress, "near_fn");
            Function far = functionAtOrCreate(farAddress, "far_fn");
            Function caller16 = functionAtOrCreate(caller16Address, "caller16");
            Function near16 = functionAtOrCreate(near16Address, "near16_fn");
            Function far16 = functionAtOrCreate(far16Address, "far16_fn");
            Function callerVoid = functionAtOrCreate(callerVoidAddress, "callerVoid");
            Function nearVoid = functionAtOrCreate(nearVoidAddress, "near_void");
            Function farVoid = functionAtOrCreate(farVoidAddress, "far_void");
            Function emulationCaller =
                functionAtOrCreate(emulationCallerAddress, "emulationCaller");
            Function nearEmulation =
                functionAtOrCreate(nearEmulationAddress, "near_emu_fn");
            Function farEmulation =
                functionAtOrCreate(farEmulationAddress, "far_emu_fn");
            Function nestedCaller =
                functionAtOrCreate(nestedCallerAddress, "nestedCaller");
            Function wrapper = functionAtOrCreate(wrapperAddress, "nested_wrapper");
            Function stackDataCaller =
                functionAtOrCreate(stackDataCallerAddress, "stackDataCaller");
            Function registerEffectsCaller =
                functionAtOrCreate(registerEffectsCallerAddress, "registerEffectsCaller");
            Function registerEffectsCallee =
                functionAtOrCreate(registerEffectsCalleeAddress, "registerEffectsCallee");

            setRegisterAbi(near, "__near");
            setRegisterAbi(far, "__far");
            setRegisterAbi16(near16, "__near");
            setRegisterAbi16(far16, "__far");
            setRegisterAbi(nearEmulation, "__near");
            setRegisterAbi(farEmulation, "__far");
            wrapper.setCallingConvention("__far");
            wrapper.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            nestedCaller.setCallingConvention("__unknowncall");
            nestedCaller.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            stackDataCaller.setCallingConvention("__unknowncall");
            stackDataCaller.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            registerEffectsCaller.setCallingConvention("__unknowncall");
            registerEffectsCaller.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            registerEffectsCallee.setCallingConvention("__far");
            registerEffectsCallee.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            emulationCaller.setCallingConvention("__unknowncall");
            emulationCaller.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            nearVoid.setCallingConvention("__near");
            nearVoid.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            farVoid.setCallingConvention("__far");
            farVoid.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            caller.setCallingConvention("__unknowncall");
            caller.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            caller16.setCallingConvention("__unknowncall");
            caller16.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
            callerVoid.setCallingConvention("__unknowncall");
            callerVoid.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);

            out.println("near=" + near.getCallingConventionName());
            out.println("far=" + far.getCallingConventionName());
            out.println("near16=" + near16.getCallingConventionName());
            out.println("far16=" + far16.getCallingConventionName());
            out.println("nearVoid=" + nearVoid.getCallingConventionName());
            out.println("farVoid=" + farVoid.getCallingConventionName());
            out.println("nearEmu=" + nearEmulation.getCallingConventionName());
            out.println("farEmu=" + farEmulation.getCallingConventionName());
            out.println("nestedWrapper=" + wrapper.getCallingConventionName());
            out.println("registerEffectsCallee=" + registerEffectsCallee.getCallingConventionName());

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
                decompileAndPrint(decompiler, callerVoid, "callerVoid", out);
                decompileAndPrint(decompiler, nearVoid, "nearVoid", out);
                decompileAndPrint(decompiler, farVoid, "farVoid", out);
                decompileAndPrint(decompiler, nestedCaller, "nestedCaller", out);
                decompileAndPrint(decompiler, wrapper, "nestedWrapper", out);
                decompileAndPrint(decompiler, stackDataCaller, "stackDataCaller", out);
                decompileAndPrint(decompiler, registerEffectsCaller, "registerEffectsCaller", out);
                decompileAndPrint(decompiler, registerEffectsCallee, "registerEffectsCallee", out);
                decompileAndPrint(decompiler, emulationCaller, "emulationCaller", out);
                decompileAndPrint(decompiler, nearEmulation, "nearEmu", out);
                decompileAndPrint(decompiler, farEmulation, "farEmu", out);
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
