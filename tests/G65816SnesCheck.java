import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;

public class G65816SnesCheck extends GhidraScript {
    private void check(boolean condition, String detail) {
        if (!condition) {
            throw new AssertionError(detail);
        }
    }

    private void rom(int address, int offset, int value) throws Exception {
        var at = toAddr(address);
        var memory = currentProgram.getMemory();
        var block = memory.getBlock(at);
        check(block.isRead() && !block.isWrite() && block.isExecute(), "ROM permissions at " + at);
        check(memory.getAddressSourceInfo(at).getFileOffset() == offset, "File offset at " + at);
        check((memory.getByte(at) & 255) == value, "ROM byte at " + at);
    }

    @Override
    protected void run() throws Exception {
        String name = currentProgram.getName();
        String mode = getScriptArgs()[0];
        var mem = currentProgram.getMemory();
        if (mode.equals("raw")) {
            check(currentProgram.getExecutableFormat().equals("Raw Binary"), "binary loader");
            check(mem.getBlocks().length == 1 && mem.getBlock(toAddr(0x7e0000)) == null, "raw map");
        }
        else {
            check(currentProgram.getExecutableFormat().equals("SNES ROM"), "auto-selected loader");
            String[] fields = name.replace(".bin", "").split("-");
            boolean hi = fields[0].equals("hi");
            int prefix = Integer.parseInt(fields[1]);
            int size = Integer.parseInt(fields[2]);
            int code = prefix + (hi ? 0x8000 : 0);
            for (int addr : new int[] { 0x008000, 0x808000, hi ? 0xc08000 : 0x808000 }) {
                rom(addr, code, 0xa9);
            }
            rom(0xffffff, prefix + size - 1, 0x72);
            if (size > 0x10000) {
                rom(hi ? 0x410000 : 0x028000, prefix + 0x10000, 0x5a);
            }
            for (int addr : new int[] { 0x002000, 0x006000, 0x802100, 0xbf7fff }) {
                check(mem.getBlock(toAddr(addr)) == null, "system hole " + addr);
            }
            if (!hi) {
                check(mem.getBlock(toAddr(0x400000)) == null && mem.getBlock(toAddr(0xf00000)) == null,
                    "unverified LoROM lower windows");
            }
            var vector = toAddr(0xfffc);
            var target = toAddr(0x8000);
            check(getDataAt(vector).getLength() == 2, "reset vector word");
            check(Arrays.stream(getReferencesFrom(vector)).anyMatch(r -> r.getToAddress().equals(target)),
                "reset reference");
            check(currentProgram.getSymbolTable().isExternalEntryPoint(target), "reset entry");
            check(getInstructionAt(target).getLength() == 2 &&
                getInstructionAt(target).getMnemonicString().equalsIgnoreCase("lda"), "reset decode");
            for (String field : new String[] { "ctx_EF", "ctx_MF", "ctx_XF" }) {
                var ctx = currentProgram.getProgramContext();
                check(BigInteger.ONE.equals(ctx.getValue(ctx.getRegister(field), target, false)), field);
            }
            for (int bank : new int[] { 0, 0x80 }) {
                var branch = toAddr((bank << 16) + 0x8002);
                new DisassembleCommand(branch, new AddressSet(branch), false).applyTo(currentProgram, monitor);
                check(getInstructionAt(branch).getFlows()[0].equals(toAddr((bank << 16) + 0x8000)),
                    "bank-local JMP at " + branch);
            }
            var wram = mem.getBlock(toAddr(0x7fffff));
            check(wram.getStart().equals(toAddr(0x7e0000)) && wram.getSize() == 0x20000 &&
                !wram.isInitialized() && wram.isWrite() && !wram.isExecute(), "physical WRAM");
            var mirror = mem.getBlock(toAddr(0xbf0012));
            check(mirror.isMapped() && mirror.isWrite() && !mirror.isExecute(), "WRAM alias");
            mem.convertToInitialized(wram, (byte) 0);
            mem.setByte(toAddr(0xbf0012), (byte) 0x53);
            check(mem.getByte(toAddr(0x7e0012)) == 0x53 && mem.getByte(toAddr(0x12)) == 0x53,
                "WRAM alias write-through");
        }
        Files.createFile(Path.of(getScriptArgs()[1], name + "." + mode));
    }
}
