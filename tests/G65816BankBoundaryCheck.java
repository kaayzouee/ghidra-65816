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
 * Characterize 65816 instruction-byte fetch at $xx:FFFF.
 *
 * The test maps LDA immediate at $00:FFFF, puts the architecturally wrapped
 * operand byte at $00:0000, and leaves a conflicting byte at linear $01:0000.
 * The current 24-bit PC model is expected to consume the linear byte instead.
 */
public class G65816BankBoundaryCheck extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected output path");
        }

        Memory memory = currentProgram.getMemory();
        Address wrappedOperandAddress = toAddr(0x000000);
        MemoryBlock lowBank = memory.createInitializedBlock(
            "bank00-low", wrappedOperandAddress, 2, (byte) 0, monitor, false);
        lowBank.setRead(true);
        lowBank.setExecute(true);
        memory.setByte(wrappedOperandAddress, (byte) 0x42);
        memory.setByte(toAddr(0x000001), (byte) 0xea);

        Address entry = toAddr(0x00ffff);
        Register contextRegister = currentProgram.getLanguage().getContextBaseRegister();
        RegisterValue context = new RegisterValue(contextRegister);
        context = context.assign(
            currentProgram.getLanguage().getRegister("ctx_MF"), BigInteger.ONE);
        context = context.assign(
            currentProgram.getLanguage().getRegister("ctx_XF"), BigInteger.ONE);
        context = context.assign(
            currentProgram.getLanguage().getRegister("ctx_EF"), BigInteger.ONE);

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
        if (bytes.length < 2) {
            throw new AssertionError("Expected immediate LDA to be at least two bytes");
        }

        Address fallThrough = instruction.getFallThrough();
        try (PrintStream out = new PrintStream(args[0])) {
            out.printf(
                "entry=%06x|mnemonic=%s|length=%d|opcode=%02x|operand=%02x|wrapped=%02x|fallthrough=%06x%n",
                entry.getOffset(), instruction.getMnemonicString(), instruction.getLength(),
                bytes[0] & 0xff, bytes[1] & 0xff,
                memory.getByte(wrappedOperandAddress) & 0xff, fallThrough.getOffset());
        }
    }
}
