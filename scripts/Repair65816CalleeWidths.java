// Repair isolated continuations after one or two adjacent SEP/REP width setters.
// @category 65816
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class Repair65816CalleeWidths extends GhidraScript {
    private int immediateLength(int opcode, int m, int x) {
        switch (opcode) {
            case 0x09: case 0x29: case 0x49: case 0x69: case 0x89:
            case 0xa9: case 0xc9: case 0xe9:
                return m == 1 ? 2 : 3;
            case 0xa0: case 0xa2: case 0xc0: case 0xe0:
                return x == 1 ? 2 : 3;
            case 0xea:
                return 1;
            default:
                return 0;
        }
    }

    private List<Address> isolatedBlock(Instruction call, Address start, int m, int x)
            throws Exception {
        List<Address> starts = new ArrayList<>();
        Address at = start;
        Address end = null;
        for (int i = 0; i < 16; i++) {
            int opcode = currentProgram.getMemory().getByte(at) & 0xff;
            starts.add(at);
            if (opcode == 0xdb || opcode == 0x60 || opcode == 0x6b) {
                end = at;
                break;
            }
            int length = immediateLength(opcode, m, x);
            if (length == 0) {
                return null;
            }
            at = at.add(length);
            if ((at.getOffset() & 0xff0000L) != (start.getOffset() & 0xff0000L)
                    || at.subtract(start) > 64) {
                return null;
            }
        }
        if (end == null || starts.size() < 2) {
            return null;
        }
        Listing listing = currentProgram.getListing();
        for (Address address = start; address.compareTo(end) <= 0; address = address.next()) {
            if (currentProgram.getSymbolTable().hasSymbol(address)
                    || listing.getDefinedDataContaining(address) != null) {
                return null;
            }
            for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(address)) {
                if (!ref.getFromAddress().equals(call.getAddress())) {
                    return null;
                }
            }
            CodeUnit unit = listing.getCodeUnitContaining(address);
            if (unit instanceof Instruction instruction) {
                if (instruction.isLengthOverridden() || instruction.isFallThroughOverridden()
                        || instruction.getFlowOverride() != FlowOverride.NONE) {
                    return null;
                }
                for (CommentType type : CommentType.values()) {
                    if (instruction.getComment(type) != null) {
                        return null;
                    }
                }
            }
        }
        return starts;
    }

    private boolean repair(Instruction call) throws Exception {
        String callType = call.getMnemonicString();
        if (!call.getFlowType().isCall()
                || (!"JSR".equals(callType) && !"JSL".equals(callType))
                || call.getFlows().length != 1 || !call.getFlows()[0].isMemoryAddress()) {
            return false;
        }
        int opcode = call.getBytes()[0] & 0xff;
        if (opcode != ("JSR".equals(callType) ? 0x20 : 0x22)
                || !call.getAddress().getAddressSpace().equals(
                    currentProgram.getAddressFactory().getDefaultAddressSpace())) {
            return false;
        }
        Listing listing = currentProgram.getListing();
        var ef = currentProgram.getRegister("ctx_EF");
        Instruction setter = listing.getInstructionAt(call.getFlows()[0]);
        int setM = -1;
        int setX = -1;
        boolean returns = false;
        String returnMnemonic = "JSR".equals(callType) ? "RTS" : "RTL";
        for (int i = 0; i < 2; i++) {
            if (setter == null || setter.getLength() != 2
                    || !BigInteger.ZERO.equals(setter.getValue(ef, false))) {
                return false;
            }
            String mnemonic = setter.getMnemonicString();
            if (!"SEP".equals(mnemonic) && !"REP".equals(mnemonic)) {
                return false;
            }
            int mask = setter.getBytes()[1] & 0xff;
            if (mask != 0x10 && mask != 0x20 && mask != 0x30) {
                return false;
            }
            int width = "SEP".equals(mnemonic) ? 1 : 0;
            if ((mask & 0x20) != 0) {
                setM = width;
            }
            if ((mask & 0x10) != 0) {
                setX = width;
            }
            Address nextAddress = setter.getFallThrough();
            Instruction next = nextAddress == null ? null : listing.getInstructionAt(nextAddress);
            if (next != null && returnMnemonic.equals(next.getMnemonicString())) {
                returns = true;
                break;
            }
            setter = next;
        }
        if (!returns) {
            return false;
        }
        Address continuation = call.getFallThrough();
        Instruction first = continuation == null ? null : listing.getInstructionAt(continuation);
        var mf = currentProgram.getRegister("ctx_MF");
        var xf = currentProgram.getRegister("ctx_XF");
        if (first == null || !BigInteger.ZERO.equals(call.getValue(ef, false))) {
            return false;
        }
        BigInteger oldM = first.getValue(mf, false);
        BigInteger oldX = first.getValue(xf, false);
        if (oldM == null || oldX == null) {
            return false;
        }
        if (!oldM.equals(call.getValue(mf, false))
                || !oldX.equals(call.getValue(xf, false))) {
            return false;
        }
        int m = setM < 0 ? oldM.intValue() : setM;
        int x = setX < 0 ? oldX.intValue() : setX;
        if (oldM.intValue() == m && oldX.intValue() == x) {
            return false;
        }
        List<Address> starts = isolatedBlock(call, continuation, m, x);
        if (starts == null) {
            return false;
        }
        RegisterValue context = call.getRegisterValue(
            currentProgram.getLanguage().getContextBaseRegister());
        if (context == null) {
            return false;
        }
        context = context.assign(mf, BigInteger.valueOf(m))
            .assign(xf, BigInteger.valueOf(x));
        int tx = currentProgram.startTransaction("Repair 65816 leaf call widths");
        boolean commit = false;
        try {
            listing.clearCodeUnits(continuation, starts.get(starts.size() - 1), true);
            currentProgram.getProgramContext().setRegisterValue(continuation, continuation, context);
            DisassembleCommand disassemble = new DisassembleCommand(continuation, null, true);
            disassemble.setInitialContext(context);
            if (!disassemble.applyTo(currentProgram, monitor)) {
                return false;
            }
            for (int i = 0; i < starts.size(); i++) {
                Instruction instruction = listing.getInstructionAt(starts.get(i));
                int size = i + 1 == starts.size()
                    ? 1 : (int) starts.get(i + 1).subtract(starts.get(i));
                if (instruction == null || instruction.getLength() != size) {
                    return false;
                }
            }
            commit = true;
            return true;
        }
        finally {
            currentProgram.endTransaction(tx, commit);
        }
    }

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguage().getLanguageID().toString().startsWith("65816:")) {
            throw new IllegalArgumentException("Expected a 65816 program");
        }
        List<Address> calls = new ArrayList<>();
        for (Instruction instruction : currentProgram.getListing().getInstructions(true)) {
            if (instruction.getFlowType().isCall()) {
                calls.add(instruction.getAddress());
            }
        }
        int repairs = 0;
        for (Address address : calls) {
            monitor.checkCancelled();
            Instruction instruction = currentProgram.getListing().getInstructionAt(address);
            if (instruction != null && repair(instruction)) {
                repairs++;
            }
        }
        if (getScriptArgs().length > 0) {
            try (PrintStream out = new PrintStream(getScriptArgs()[0])) {
                out.println("REPAIRED|" + repairs);
            }
        }
        println("65816 simple leaf continuations repaired: " + repairs);
    }
}
