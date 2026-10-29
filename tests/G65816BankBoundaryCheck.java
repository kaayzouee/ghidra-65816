import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;
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

    private void checkBankStartCoexistence(
            PrintStream out, RegisterValue context) throws Exception {
        Address bank0Instruction = toAddr(0x00fffe);
        Address bank1Instruction = toAddr(0x010000);
        DisassembleCommand command = new DisassembleCommand(bank1Instruction, null, false);
        command.setInitialContext(context);

        boolean applied = false;
        String status = "not-run";
        try {
            applied = command.applyTo(currentProgram, monitor);
            status = command.getStatusMsg();
        }
        catch (Exception exception) {
            status = exception.getClass().getSimpleName();
        }

        Instruction bank0 = currentProgram.getListing().getInstructionAt(bank0Instruction);
        Instruction bank1 = currentProgram.getListing().getInstructionAt(bank1Instruction);
        boolean bank1IsNop = bank1 != null && "NOP".equals(bank1.getMnemonicString());
        boolean coexist = bank0 != null && bank1IsNop;
        out.printf(
            "case=coexist|coexists=%d|bank0_inst=%d|bank1_inst=%d|bank1_mnemonic=%s|command_applied=%d|command_status=%s%n",
            coexist ? 1 : 0, bank0 != null ? 1 : 0, bank1 != null ? 1 : 0,
            bank1 != null ? bank1.getMnemonicString() : "none",
            applied ? 1 : 0, status.replace('|', '/').replace(' ', '_'));
    }

    /**
     * Experimental parser-only adapter: fetch instruction bytes from the same PBR while
     * wrapping the low 16-bit PC. This proves byte selection is possible at the Language.parse
     * boundary; it does not fix the normal disassembler or Ghidra's contiguous code-unit model.
     */
    private static class BankWrappedMemBuffer implements MemBuffer {
        private final Memory memory;
        private final Address start;

        BankWrappedMemBuffer(Memory memory, Address start) {
            this.memory = memory;
            this.start = start;
        }

        private Address addressAt(int offset) {
            long bankBase = start.getOffset() & ~0xffffL;
            long pc = (start.getOffset() + offset) & 0xffffL;
            return start.getAddressSpace().getAddress(bankBase | pc);
        }

        @Override
        public byte getByte(int offset) throws ghidra.program.model.mem.MemoryAccessException {
            return memory.getByte(addressAt(offset));
        }

        @Override
        public int getBytes(byte[] bytes, int offset) {
            int count = 0;
            for (int i = 0; i < bytes.length; i++) {
                try {
                    bytes[i] = getByte(offset + i);
                    count++;
                }
                catch (ghidra.program.model.mem.MemoryAccessException e) {
                    break;
                }
            }
            return count;
        }

        @Override public Address getAddress() { return start; }
        @Override public Memory getMemory() { return memory; }
        @Override public boolean isBigEndian() { return false; }

        @Override
        public short getShort(int offset) throws ghidra.program.model.mem.MemoryAccessException {
            return (short) readUnsigned(offset, 2);
        }

        @Override
        public int getInt(int offset) throws ghidra.program.model.mem.MemoryAccessException {
            return (int) readUnsigned(offset, 4);
        }

        @Override
        public long getLong(int offset) throws ghidra.program.model.mem.MemoryAccessException {
            return readUnsigned(offset, 8);
        }

        @Override
        public BigInteger getBigInteger(int offset, int size, boolean signed)
                throws ghidra.program.model.mem.MemoryAccessException {
            if (size < 1 || size > 8) {
                throw new IllegalArgumentException("Unsupported test read size: " + size);
            }
            BigInteger value = BigInteger.ZERO;
            for (int i = size - 1; i >= 0; i--) {
                value = value.shiftLeft(8).or(BigInteger.valueOf(getByte(offset + i) & 0xff));
            }
            if (signed && value.testBit(size * 8 - 1)) {
                value = value.subtract(BigInteger.ONE.shiftLeft(size * 8));
            }
            return value;
        }

        private long readUnsigned(int offset, int size)
                throws ghidra.program.model.mem.MemoryAccessException {
            long value = 0;
            for (int i = size - 1; i >= 0; i--) {
                value = (value << 8) | (getByte(offset + i) & 0xffL);
            }
            return value;
        }
    }

    /** Adapts one parsed prototype to the context interface used by operand evaluation. */
    private static class FixedInstructionContext implements InstructionContext {
        private final Address address;
        private final ProcessorContext processorContext;
        private final MemBuffer buffer;
        private final ghidra.program.model.lang.ParserContext parserContext;

        FixedInstructionContext(
                Address address, ProcessorContext processorContext, MemBuffer buffer,
                ghidra.program.model.lang.ParserContext parserContext) {
            this.address = address;
            this.processorContext = processorContext;
            this.buffer = buffer;
            this.parserContext = parserContext;
        }

        @Override public Address getAddress() { return address; }
        @Override public ghidra.program.model.lang.ProcessorContextView getProcessorContext() {
            return processorContext;
        }
        @Override public MemBuffer getMemBuffer() { return buffer; }
        @Override public ghidra.program.model.lang.ParserContext getParserContext() {
            return parserContext;
        }
        @Override public ghidra.program.model.lang.ParserContext getParserContext(Address ignored) {
            return parserContext;
        }
    }

    /** Minimal fixed context used only to invoke Language.parse with the test's M/X/E state. */
    private static class FixedProcessorContext implements ProcessorContext {
        private final Language language;
        private final RegisterValue baseValue;

        FixedProcessorContext(Language language, RegisterValue baseValue) {
            this.language = language;
            this.baseValue = baseValue;
        }

        @Override public Register getBaseContextRegister() {
            return language.getContextBaseRegister();
        }
        @Override public java.util.List<Register> getRegisters() {
            return language.getRegisters();
        }
        @Override public Register getRegister(String name) {
            return language.getRegister(name);
        }
        @Override public RegisterValue getRegisterValue(Register register) {
            if (register == null || baseValue == null) return null;
            if (register.equals(baseValue.getRegister())) return baseValue;
            return baseValue.getRegisterValue(register);
        }
        @Override public BigInteger getValue(Register register, boolean signed) {
            RegisterValue value = getRegisterValue(register);
            if (value == null || !value.hasAnyValue()) return null;
            BigInteger result = value.getUnsignedValueIgnoreMask();
            if (signed && result.testBit(register.getBitLength() - 1)) {
                result = result.subtract(BigInteger.ONE.shiftLeft(register.getBitLength()));
            }
            return result;
        }
        @Override public boolean hasValue(Register register) {
            RegisterValue value = getRegisterValue(register);
            return value != null && value.hasAnyValue();
        }
        @Override public void setValue(Register register, BigInteger value) {
            throw new UnsupportedOperationException("Fixed test context");
        }
        @Override public void setRegisterValue(RegisterValue value) {
            throw new UnsupportedOperationException("Fixed test context");
        }
        @Override public void clearRegister(Register register) {
            throw new UnsupportedOperationException("Fixed test context");
        }
    }

    private void probeWrappedParser(
            PrintStream out, Memory memory, RegisterValue context, String label,
            long entryOffset, int expectedLength, long expectedOperand,
            int wrappedOffset, int expectedWrappedByte) throws Exception {
        Address entry = toAddr(entryOffset);
        BankWrappedMemBuffer buffer = new BankWrappedMemBuffer(memory, entry);
        FixedProcessorContext processorContext =
            new FixedProcessorContext(currentProgram.getLanguage(), context);
        InstructionPrototype prototype =
            currentProgram.getLanguage().parse(buffer, processorContext, false);
        ghidra.program.model.lang.ParserContext parserContext =
            prototype.getParserContext(buffer, processorContext);
        InstructionContext instructionContext = new FixedInstructionContext(
            entry, processorContext, buffer, parserContext);
        Object[] inputObjects = prototype.getInputObjects(instructionContext);
        long operand = -1;
        StringBuilder scalarInputs = new StringBuilder();
        for (Object input : inputObjects) {
            if (input instanceof Scalar) {
                long value = ((Scalar) input).getUnsignedValue();
                if (scalarInputs.length() > 0) scalarInputs.append(",");
                scalarInputs.append(Long.toHexString(value));
                if (expectedOperand >= 0 && value == expectedOperand) operand = value;
            }
        }

        StringBuilder parsedBytes = new StringBuilder();
        for (int i = 0; i < prototype.getLength(); i++) {
            parsedBytes.append(String.format("%02x", buffer.getByte(i) & 0xff));
        }
        int wrappedByte = buffer.getByte(wrappedOffset) & 0xff;
        String operandText = expectedOperand >= 0 ? Long.toHexString(operand) : "none";
        out.printf(
            "case=parserprobe|label=%s|entry=%06x|length=%d|operand=%s|wrapped_offset=%d|wrapped_byte=%02x|bytes=%s|scalars=%s%n",
            label, entry.getOffset(), prototype.getLength(), operandText,
            wrappedOffset, wrappedByte, parsedBytes, scalarInputs);

        if (prototype.getLength() != expectedLength || wrappedByte != expectedWrappedByte ||
                (expectedOperand >= 0 && operand != expectedOperand)) {
            throw new AssertionError(
                "Bank-wrapped Language.parse probe failed for " + label +
                ": expected length " + expectedLength + ", wrapped byte 0x" +
                Integer.toHexString(expectedWrappedByte) +
                (expectedOperand >= 0 ? ", operand 0x" + Long.toHexString(expectedOperand) : "") +
                "; got length " + prototype.getLength() + ", wrapped byte 0x" +
                Integer.toHexString(wrappedByte) +
                ", operand " + operandText + ", bytes " + parsedBytes +
                ", scalar inputs [" + scalarInputs + "]");
        }
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
            checkBankStartCoexistence(out, context);
            probeWrappedParser(
                out, memory, context, "absolute3", 0x00fffe, 3, -1, 2, 0x56);
            probeWrappedParser(
                out, memory, context, "immediate2", 0x02ffff, 2, 0x42, 1, 0x42);
            probeWrappedParser(
                out, memory, context, "single1", 0x04ffff, 1, -1, 1, 0x18);
        }
    }
}
