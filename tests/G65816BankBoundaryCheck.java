import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Characterize 65816 instruction-byte fetch and fall-through at program-bank boundaries.
 *
 * Three instructions contrast bytes in the next linear bank with distinct bytes at the
 * architecturally wrapped start of their current bank:
 * - LDA absolute at $00:FFFE (three bytes)
 * - LDA immediate at $02:FFFF (two bytes)
 * - NOP at $04:FFFF (one byte)
 */
public class G65816BankBoundaryCheck extends GhidraScript {
    private MemoryBlock createExecutableBlock(
            Memory memory, String name, long start, int length, byte initialValue)
            throws Exception {
        MemoryBlock block = memory.createInitializedBlock(
            name, toAddr(start), length, initialValue, monitor, false);
        block.setRead(true);
        block.setExecute(true);
        return block;
    }

    private void setBytes(Memory memory, long start, byte[] bytes) throws Exception {
        for (int i = 0; i < bytes.length; i++) {
            memory.setByte(toAddr(start + i), bytes[i]);
        }
    }

    private void disassembleAndPrint(
            PrintStream out, Memory memory, long entryOffset, long wrappedAddress, String label,
            RegisterValue context) throws Exception {
        Address entry = toAddr(entryOffset);
        DisassembleCommand command = new DisassembleCommand(entry, null, false);
        command.setInitialContext(context);
        if (!command.applyTo(currentProgram, monitor)) {
            throw new IllegalStateException(
                "Disassembly failed at " + entry + ": " + command.getStatusMsg());
        }

        Instruction instruction = currentProgram.getListing().getInstructionAt(entry);
        if (instruction == null) {
            throw new AssertionError("No instruction decoded at " + entry);
        }
        byte[] bytes = instruction.getBytes();
        Address fallThrough = instruction.getFallThrough();
        out.printf("case=%s|entry=%06x|mnemonic=%s|length=%d|bytes=",
            label, entry.getOffset(), instruction.getMnemonicString(),
            instruction.getLength());
        for (byte value : bytes) {
            out.printf("%02x", value & 0xff);
        }
        out.printf("|wrapped=%02x|fallthrough=%06x%n",
            memory.getByte(toAddr(wrappedAddress)) & 0xff, fallThrough.getOffset());
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected output path");
        }

        Memory memory = currentProgram.getMemory();

        // The imported ROM starts at $00:FFFE. Its third byte lands at linear $01:0000.
        // Hardware instruction fetch should wrap that third byte to $00:0000 instead.
        createExecutableBlock(memory, "bank00-low", 0x000000, 2, (byte) 0);
        setBytes(memory, 0x000000, new byte[] {0x56, (byte) 0xea});

        // Two-byte instruction at $02:FFFF: linear operand is $99, wrapped operand is $42.
        createExecutableBlock(memory, "bank02-linear", 0x02ffff, 2, (byte) 0);
        setBytes(memory, 0x02ffff, new byte[] {(byte) 0xa9, (byte) 0x99});
        createExecutableBlock(memory, "bank02-low", 0x020000, 2, (byte) 0);
        setBytes(memory, 0x020000, new byte[] {0x42, (byte) 0xea});

        // One-byte instruction at $04:FFFF: linear fall-through is $05:0000,
        // but program-bank-local PC wrap should land at $04:0000.
        createExecutableBlock(memory, "bank04-end", 0x04ffff, 1, (byte) 0xea);
        createExecutableBlock(memory, "bank04-low", 0x040000, 2, (byte) 0);
        setBytes(memory, 0x040000, new byte[] {0x18, (byte) 0xea});

        Register contextRegister = currentProgram.getLanguage().getContextBaseRegister();
        RegisterValue context = new RegisterValue(contextRegister);
        context = context.assign(
            currentProgram.getLanguage().getRegister("ctx_MF"), BigInteger.ONE);
        context = context.assign(
            currentProgram.getLanguage().getRegister("ctx_XF"), BigInteger.ONE);
        context = context.assign(
            currentProgram.getLanguage().getRegister("ctx_EF"), BigInteger.ONE);

        try (PrintStream out = new PrintStream(args[0])) {
            disassembleAndPrint(out, memory, 0x00fffe, 0x000000, "absolute3", context);
            disassembleAndPrint(out, memory, 0x02ffff, 0x020000, "immediate2", context);
            disassembleAndPrint(out, memory, 0x04ffff, 0x040000, "single1", context);
        }
    }
}
