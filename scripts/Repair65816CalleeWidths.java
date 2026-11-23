// Repair short, isolated continuations after direct calls to SEP/REP + RTS/RTL leaves.
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

    private List<Address> isolatedBlock(Instruction call, Address start, int width)
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
            int length = immediateLength(opcode, width, width);
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
        Instruction setter = listing.getInstructionAt(call.getFlows()[0]);
        if (setter == null || setter.getLength() != 2
                || (!"SEP".equals(setter.getMnemonicString())
                    && !"REP".equals(setter.getMnemonicString()))
                || (setter.getBytes()[1] & 0xff) != 0x30) {
            return false;
        }
        Instruction ret = listing.getInstructionAt(setter.getFallThrough());
        if (ret == null || !("JSR".equals(callType) ? "RTS" : "RTL")
                .equals(ret.getMnemonicString())) {
            return false;
        }
        Address continuation = call.getFallThrough();
        Instruction first = continuation == null ? null : listing.getInstructionAt(continuation);
        var mf = currentProgram.getRegister("ctx_MF");
        var xf = currentProgram.getRegister("ctx_XF");
        var ef = currentProgram.getRegister("ctx_EF");
        if (first == null || !BigInteger.ZERO.equals(call.getValue(ef, false))
                || !BigInteger.ZERO.equals(setter.getValue(ef, false))) {
            return false;
        }
        BigInteger oldM = first.getValue(mf, false);
        BigInteger oldX = first.getValue(xf, false);
        if (oldM == null || oldX == null) {
            return false;
        }
        int width = "SEP".equals(setter.getMnemonicString()) ? 1 : 0;
        if (oldM.intValue() == width && oldX.intValue() == width) {
            return false;
        }
        List<Address> starts = isolatedBlock(call, continuation, width);
        if (starts == null) {
            return false;
        }
        RegisterValue context = call.getRegisterValue(
            currentProgram.getLanguage().getContextBaseRegister());
        if (context == null) {
            return false;
        }
        context = context.assign(mf, BigInteger.valueOf(width))
            .assign(xf, BigInteger.valueOf(width));
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
