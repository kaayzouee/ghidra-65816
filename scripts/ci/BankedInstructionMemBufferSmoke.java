/* Standalone smoke test compiled against the patch and the pinned Ghidra binaries. */
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.mem.BankedInstructionMemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class BankedInstructionMemBufferSmoke {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        AddressSpace space = new GenericAddressSpace("banked", 24, AddressSpace.TYPE_RAM, 0);
        Map<Long, Byte> bytes = new HashMap<>();
        bytes.put(0x00fffeL, (byte) 0xad);
        bytes.put(0x00ffffL, (byte) 0x34);
        bytes.put(0x000000L, (byte) 0x56);
        bytes.put(0x010000L, (byte) 0xea);
        bytes.put(0x02ffffL, (byte) 0xa9);
        bytes.put(0x020000L, (byte) 0x42);
        bytes.put(0x030000L, (byte) 0x99);
        bytes.put(0x04ffffL, (byte) 0xea);
        bytes.put(0x040000L, (byte) 0x18);
        bytes.put(0x050000L, (byte) 0x00);

        Memory memory = (Memory) Proxy.newProxyInstance(
            Memory.class.getClassLoader(), new Class<?>[] {Memory.class},
            (proxy, method, arguments) -> {
                if (method.getName().equals("isBigEndian")) return false;
                if (method.getName().equals("getByte")) {
                    Address address = (Address) arguments[0];
                    Byte value = bytes.get(address.getOffset());
                    if (value == null) throw new MemoryAccessException("unmapped: " + address);
                    return value;
                }
                throw new UnsupportedOperationException(method.getName());
            });

        BankedInstructionMemBuffer absolute =
            new BankedInstructionMemBuffer(memory, space.getAddress(0x00fffe), 16);
        byte[] a = new byte[3];
        check(absolute.getBytes(a, 0) == 3, "absolute byte count");
        check((a[0] & 0xff) == 0xad && (a[1] & 0xff) == 0x34 &&
            (a[2] & 0xff) == 0x56, "three-byte bank-wrapped instruction");
        check(absolute.getInstructionAddress(3).getOffset() == 0x000001,
            "three-byte inst_next must preserve bank");
        check((absolute.getShort(1) & 0xffff) == 0x5634, "wrapped little-endian word");
        check(absolute.getBigInteger(0, 3, false).equals(new BigInteger("5634ad", 16)),
            "wrapped BigInteger");
        check((absolute.getByte(2) & 0xff) != (bytes.get(0x010000L) & 0xff),
            "next-bank byte must not replace wrapped operand");

        BankedInstructionMemBuffer immediate =
            new BankedInstructionMemBuffer(memory, space.getAddress(0x02ffff), 16);
        check((immediate.getByte(1) & 0xff) == 0x42, "immediate from same bank");
        check(immediate.getInstructionAddress(2).getOffset() == 0x020001,
            "two-byte next address must preserve bank");
        check((immediate.getShort(0) & 0xffff) == 0x42a9,
            "two-byte opcode/operand fetch");

        BankedInstructionMemBuffer single =
            new BankedInstructionMemBuffer(memory, space.getAddress(0x04ffff), 16);
        check(single.getInstructionAddress(1).getOffset() == 0x040000,
            "one-byte fall-through must preserve bank");
        check((single.getByte(1) & 0xff) == 0x18, "one-byte wrapped next opcode");
        check(single.getBytes(new byte[3], 0) == 2,
            "partial reads must stop when wrapped memory is unavailable");

        try {
            new BankedInstructionMemBuffer(memory, space.getAddress(0x04ffff), 0);
            throw new AssertionError("invalid PC width accepted");
        }
        catch (IllegalArgumentException expected) {
            // expected
        }
        System.out.println("BANKED BUFFER SMOKE PASS: bytes, next addresses, endian reads, partial reads");
    }
}
