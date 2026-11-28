package ghidra65816.snes;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;
import ghidra.app.util.bin.ByteArrayProvider;

class SnesCartridgeTest {
    private static void header(byte[] image, int start, boolean hi, int sizeCode) {
        Arrays.fill(image, start, start + 21, (byte) 'A');
        image[start + 21] = (byte) (hi ? 0x31 : 0x20);
        image[start + 23] = (byte) sizeCode;
        image[start + 61] = (byte) 0x80;
    }

    private static SnesCartridge detect(byte[] image) throws IOException {
        try (var file = new ByteArrayProvider(image)) {
            return SnesCartridge.detect(file);
        }
    }

    @Test
    void geometryAndPrefix() throws Exception {
        for (boolean hi : new boolean[] { false, true }) {
            for (int size = hi ? 0x10000 : 0x8000; size <= 0x400000; size *= 2) {
                for (int prefix : new int[] { 0, 512 }) {
                    byte[] image = new byte[size + prefix];
                    int start = prefix + (hi ? 0xffc0 : 0x7fc0);
                    header(image, start, hi, Integer.numberOfTrailingZeros(size) - 10);
                    var detected = detect(image);
                    assertEquals(new SnesCartridge(hi, prefix, size, 0x8000), detected);
                    var windows = SnesMemoryMap.plan(detected);
                    assertEquals(size, windows.stream().filter(w -> w.kind() == SnesMemoryMap.Kind.ROM)
                        .mapToInt(SnesMemoryMap.Window::size).sum());
                    Arrays.fill(image, start, start + 21, (byte) 0);
                    assertNull(detect(image));
                    image[start + 28] = image[start + 29] = -1;
                    assertNotNull(detect(image));
                }
            }
        }
    }

    @Test
    void malformedAndCompetingHeaders() throws Exception {
        byte[] image = new byte[0x10000];
        header(image, 0x7fc0, false, 6);
        for (int[] field : new int[][] { {21, 0x23}, {22, 2}, {24, 1}, {23, 255}, {61, 0x7f} }) {
            byte[] altered = image.clone();
            altered[0x7fc0 + field[0]] = (byte) field[1];
            assertNull(detect(altered));
        }
        header(image, 0xffc0, true, 6);
        assertNull(detect(image));
        image[0xffc0 + 22] = 0x13;
        assertNull(detect(image));
        for (int size : new int[] { 0, 512, 0x7fff, 0xffff, 0x18000, 0x410000 }) {
            assertNull(detect(Arrays.copyOf(image, size)));
        }
        new Random(65816).nextBytes(image);
        assertNull(detect(image));
    }
}
