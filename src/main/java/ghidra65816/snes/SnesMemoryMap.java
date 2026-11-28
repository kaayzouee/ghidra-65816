package ghidra65816.snes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

final class SnesMemoryMap {
    enum Kind { ROM, WRAM, ALIAS }
    record Window(Kind kind, int start, int size, int source, boolean ram) {}

    static List<Window> plan(SnesCartridge cart) throws IOException {
        var windows = new ArrayList<Window>();
        int stride = cart.bankSize();
        for (int offset = 0; offset < cart.size(); offset += stride) {
            windows.add(new Window(Kind.ROM, cart.romAddress(offset), stride, offset, false));
        }
        windows.add(new Window(Kind.WRAM, 0x7e0000, 0x20000, 0, true));
        for (int bank = 0; bank < 256; bank++) {
            if (bank == 0x7e || bank == 0x7f) {
                continue;
            }
            int base = bank << 16;
            boolean system = (bank & 0x40) == 0;
            if (system) {
                windows.add(new Window(Kind.ALIAS, base, 0x2000, 0x7e0000, true));
            }
            int low = cart.hiRom() && !system ? 0 : 0x8000;
            int offset = (bank * stride + (cart.hiRom() ? low : 0)) & (cart.size() - 1);
            int source = cart.romAddress(offset);
            if (base + low != source) {
                windows.add(new Window(Kind.ALIAS, base + low, 0x10000 - low, source, false));
            }
        }

        var ranges = new TreeMap<Integer, Window>();
        for (Window window : windows) {
            int end = window.start + window.size;
            var previous = ranges.lowerEntry(end);
            if (window.start < 0 || end > 0x1000000 || window.size <= 0 ||
                    (previous != null && previous.getKey() + previous.getValue().size > window.start)) {
                throw new IOException("Overlapping or out-of-bus SNES window at " + window.start);
            }
            if (window.kind == Kind.ROM && (long) window.source + window.size > cart.size()) {
                throw new IOException("ROM window exceeds payload");
            }
            if (window.kind == Kind.ALIAS) {
                var entry = ranges.floorEntry(window.source);
                if (entry == null || entry.getValue().kind == Kind.ALIAS ||
                        window.source + window.size > entry.getKey() + entry.getValue().size ||
                        window.ram != entry.getValue().ram) {
                    throw new IOException("Invalid SNES alias backing at " + window.source);
                }
            }
            ranges.put(window.start, window);
        }
        return windows;
    }
}
