import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;

public class G65816CalleeWidthCheck extends GhidraScript {
    private Instruction require(long offset, String mnemonic) {
        Instruction instruction = currentProgram.getListing().getInstructionAt(toAddr(offset));
        if (instruction == null || !mnemonic.equals(instruction.getMnemonicString())) {
            throw new AssertionError(String.format(
                "%06x: expected %s, got %s", offset, mnemonic, instruction));
        }
        return instruction;
    }

    @Override
    protected void run() throws Exception {
        var lang = currentProgram.getLanguage();
        RegisterValue native16 = new RegisterValue(lang.getContextBaseRegister());
        for (String register : new String[] { "ctx_MF", "ctx_XF", "ctx_EF" }) {
            native16 = native16.assign(lang.getRegister(register), BigInteger.ZERO);
        }

        for (long entry : new long[] { 0x8200, 0x8240, 0x8280, 0x82c0, 0x8300, 0x8340 }) {
            Address start = toAddr(entry);
            DisassembleCommand command = new DisassembleCommand(start, null, true);
            command.setInitialContext(native16);
            if (!command.applyTo(currentProgram, monitor)) {
                throw new AssertionError("Disassembly failed at " + start + ": "
                    + command.getStatusMsg());
            }
            createFunction(start, null);
        }

        analyzeAll(currentProgram);
        currentProgram.getSymbolTable().createLabel(
            toAddr(0x8305), "PRESERVED_USER_CODE", SourceType.USER_DEFINED);
        runScript("Repair65816CalleeWidths.java", new String[] { getScriptArgs()[1] });
        require(0x8202, "JSR");
        require(0x8210, "SEP");
        require(0x8212, "RTS");
        require(0x8242, "JSR");
        require(0x8250, "NOP");
        require(0x8251, "RTS");
        require(0x8282, "JSR");
        require(0x8290, "BNE");
        require(0x8292, "SEP");
        require(0x8294, "RTS");
        require(0x82c2, "JSR");
        require(0x82d0, "REP");
        require(0x82d2, "RTS");
        require(0x8302, "JSR");
        require(0x8310, "SEP");
        require(0x8342, "JSL");
        require(0x8350, "SEP");
        require(0x8352, "RTL");

        try (PrintStream out = new PrintStream(getScriptArgs()[0])) {
            for (long entry : new long[] { 0x8200, 0x8240, 0x8280, 0x82c0, 0x8300, 0x8340 }) {
                long postCall = entry + (entry == 0x8340 ? 6 : 5);
                Instruction lda = require(postCall, "LDA");
                Instruction ldx = currentProgram.getListing().getInstructionAt(toAddr(postCall + 2));
                if (ldx == null || !"LDX".equals(ldx.getMnemonicString())) {
                    ldx = currentProgram.getListing().getInstructionAt(toAddr(postCall + 3));
                }
                int indexLength = ldx != null && "LDX".equals(ldx.getMnemonicString())
                    ? ldx.getLength() : 0;
                out.printf("%06x|%d|%d%n", entry, lda.getLength(), indexLength);
            }
        }
    }
}
