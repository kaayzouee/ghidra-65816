package ghidra65816;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra65816.snes.SnesRomLoader;

class SnesImportCleanupTest {
    @BeforeAll
    static void initialize() throws Exception {
        PcodeEmulatorRegressionTest.initializeGhidra();
    }

    @Test
    void discardsPartialPrograms() throws Exception {
        byte[] image = new byte[0x8000];
        image[0x7fd5] = 0x20;
        image[0x7fd7] = 5;
        image[0x7fdc] = image[0x7fdd] = -1;
        // LDA at FFFB overlaps the two-byte reset vector data item.
        image[0x7ffb] = (byte) 0xa9;
        image[0x7ffc] = (byte) 0xfb;
        image[0x7ffd] = -1;
        try (var file = new ByteArrayProvider("cleanup.sfc", image)) {
            for (boolean cancel : new boolean[] { true, false }) {
                var loader = new SnesRomLoader() {
                    Program partial;
                    @Override
                    protected void load(Program program, ImporterSettings settings)
                            throws IOException, CancelledException {
                        partial = program;
                        super.load(program, settings);
                    }
                };
                var monitor = new TaskMonitorAdapter(true) {
                    @Override
                    public void checkCancelled() throws CancelledException {
                        if (cancel && loader.partial != null && loader.partial.getMemory().getNumAddresses() > 0) {
                            throw new CancelledException();
                        }
                    }
                };
                var spec = loader.findSupportedLoadSpecs(file).iterator().next();
                var settings = new ImporterSettings(file, file.getName(), null, "/", false, spec,
                    List.of(), this, new MessageLog(), monitor);
                if (cancel) {
                    assertThrows(CancelledException.class, () -> loader.load(settings));
                }
                else {
                    var failure = assertThrows(IOException.class, () -> loader.load(settings));
                    assertTrue(failure.getMessage().contains("Cannot decode"), failure.toString());
                }
                assertTrue(loader.partial.isClosed());
            }
        }
    }
}
