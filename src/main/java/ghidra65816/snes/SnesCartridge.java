package ghidra65816.snes;

import java.io.IOException;
import ghidra.app.util.bin.ByteProvider;

/** Geometry accepted by the ROM-only loader. All offsets here exclude the copier prefix. */
record SnesCartridge(boolean hiRom, int prefix, int size, int reset) {
    static SnesCartridge detect(ByteProvider file) throws IOException {
        long length = file.length();
        int prefix = (int) (length % 0x8000);
        long size = length - prefix;
        if ((prefix != 0 && prefix != 512) || size < 0x8000 || size > 0x400000 ||
                Long.bitCount(size) != 1) {
            return null;
        }
        SnesCartridge result = null;
        for (int header : new int[] { 0x7fc0, 0xffc0 }) {
            if (header + 64 > size) {
                continue;
            }
            byte[] bytes = file.readBytes(prefix + header, 64);
            int reset = word(bytes, 60);
            if (reset < 0x8000 || bytes[23] != Long.numberOfTrailingZeros(size) - 10) {
                continue;
            }
            boolean checksumPair = (word(bytes, 28) ^ word(bytes, 30)) == 0xffff;
            boolean title = true;
            boolean nonblank = false;
            for (int i = 0; i < 21; i++) {
                title &= bytes[i] >= 32 && bytes[i] <= 126;
                nonblank |= bytes[i] > 32;
            }
            if (!checksumPair && !(title && nonblank)) {
                continue;
            }
            boolean hiRom = header == 0xffc0;
            int mode = Byte.toUnsignedInt(bytes[21]) & ~0x10;
            // A second credible header, including one for an unsupported board, is ambiguous.
            if (result != null || mode != (hiRom ? 0x21 : 0x20) ||
                    bytes[22] != 0 || bytes[24] != 0 || reset == 0xfffc || reset == 0xfffd) {
                return null;
            }
            result = new SnesCartridge(hiRom, prefix, (int) size, reset);
        }
        return result;
    }

    private static int word(byte[] bytes, int offset) {
        return Byte.toUnsignedInt(bytes[offset]) | Byte.toUnsignedInt(bytes[offset + 1]) << 8;
    }

    int bankSize() {
        return hiRom ? 0x10000 : 0x8000;
    }

    int romAddress(int offset) {
        return hiRom ? 0xc00000 + offset :
            0x808000 + (offset / 0x8000) * 0x10000 + offset % 0x8000;
    }
}
