package ghidra65816;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import java.util.concurrent.TimeUnit;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.DefaultLanguageService;

/** Small runtime tests for generated 65816 p-code. */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class PcodeEmulatorRegressionTest {
    private static final long CODE_ADDRESS = 0x1000;
    private static final long DATA_ADDRESS = 0x2000;
    private static Language language;

    private record Run(PcodeEmulator emulator, PcodeThread<byte[]> thread, AddressSpace space) {}

    @BeforeAll
    static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assertNotNull(installDir, "GHIDRA_INSTALL_DIR must be set by the test workflow");

        String externalModules = System.getenv("GHIDRA_EXTERNAL_MODULES");
        assertNotNull(externalModules, "GHIDRA_EXTERNAL_MODULES must point to the compiled language module");
        System.setProperty("ghidra.external.modules", externalModules);

        if (!Application.isInitialized()) {
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)),
                new HeadlessGhidraApplicationConfiguration());
        }
        language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("65816:LE:16:default"));
    }

    private static Run start(byte[] code) {
        return startAt(CODE_ADDRESS, code);
    }

    private static Run startAt(long codeAddress, byte[] code) {
        PcodeEmulator emulator = new PcodeEmulator(language);
        AddressSpace space = language.getDefaultSpace();
        emulator.getSharedState().setVar(space, codeAddress, code.length, false, code);
        return startAt(emulator, space, codeAddress);
    }

    private static Run startAt(long codeAddress) {
        PcodeEmulator emulator = new PcodeEmulator(language);
        AddressSpace space = language.getDefaultSpace();
        return startAt(emulator, space, codeAddress);
    }

    private static Run startAt(
            PcodeEmulator emulator, AddressSpace space, long codeAddress) {
        PcodeThread<byte[]> thread = emulator.newThread();
        thread.overrideCounter(space.getAddress(codeAddress));
        thread.overrideContextWithDefault();
        Run run = new Run(emulator, thread, space);
        writeRegister(run, "DBR", 0);
        return run;
    }

    private static void writeMemory(Run run, long address, byte[] bytes) {
        run.emulator().getSharedState().setVar(
            run.space(), address, bytes.length, false, bytes);
    }

    private static long readMemory(Run run, long address, int size) {
        byte[] bytes = run.emulator().getSharedState().getVar(
            run.space(), address, size, false, Reason.INSPECT);
        return run.emulator().getArithmetic().toLong(bytes, Purpose.INSPECT);
    }

    private static void writeRegister(Run run, String name, long value) {
        Register register = language.getRegister(name);
        assertNotNull(register, "Missing 65816 register: " + name);
        PcodeArithmetic<byte[]> arithmetic = run.emulator().getArithmetic();
        run.thread().getState().setVar(
            register, arithmetic.fromConst(value, register.getNumBytes()));
    }

    private static void setContextBit(Run run, String name, long value) {
        Register contextBit = language.getRegister(name);
        assertNotNull(contextBit, "Missing 65816 context field: " + name);
        RegisterValue context = run.thread().getContext()
            .assign(contextBit, BigInteger.valueOf(value));
        run.thread().overrideContext(context);
    }

    private static long readRegister(Run run, String name) {
        Register register = language.getRegister(name);
        assertNotNull(register, "Missing 65816 register: " + name);
        PcodeArithmetic<byte[]> arithmetic = run.emulator().getArithmetic();
        return arithmetic.toLong(
            run.thread().getState().getVar(register, Reason.INSPECT), Purpose.INSPECT);
    }

    private static void executeOne(Run run) throws Exception {
        run.thread().stepInstruction();
    }

    @Test
    void phpEmulationPushesReservedAndBreakBitsAsOnes() throws Exception {
        Run run = start(new byte[] {0x08}); // PHP
        setContextBit(run, "ctx_EF", 1);
        writeRegister(run, "SP", 0x01f0);
        writeRegister(run, "NF", 1);
        writeRegister(run, "VF", 0);
        writeRegister(run, "DF", 1);
        writeRegister(run, "IF", 1);
        writeRegister(run, "ZF", 0);
        writeRegister(run, "CF", 1);
        writeRegister(run, "BF", 0);

        executeOne(run);

        assertEquals(0xbd, readMemory(run, 0x01f0, 1),
            "PHP stack image must set reserved bit 5 and synthetic B bit 4");
        assertEquals(0x01ef, readRegister(run, "SP"));
    }

    @Test
    void plpEmulationRestoresLiveFlagsButIgnoresBreakBit() throws Exception {
        Run run = start(new byte[] {0x28}); // PLP
        setContextBit(run, "ctx_EF", 1);
        writeRegister(run, "SP", 0x01ee);
        writeRegister(run, "BF", 0);
        writeRegister(run, "NF", 0);
        writeRegister(run, "VF", 0);
        writeRegister(run, "DF", 1);
        writeRegister(run, "IF", 1);
        writeRegister(run, "ZF", 0);
        writeRegister(run, "CF", 0);
        writeMemory(run, 0x01ef, new byte[] {(byte) 0xf3});

        executeOne(run);

        assertEquals(1, readRegister(run, "NF"));
        assertEquals(1, readRegister(run, "VF"));
        assertEquals(0, readRegister(run, "DF"));
        assertEquals(0, readRegister(run, "IF"));
        assertEquals(1, readRegister(run, "ZF"));
        assertEquals(1, readRegister(run, "CF"));
        assertEquals(0, readRegister(run, "BF"),
            "B is not a persistent live flag in emulation mode");
        assertEquals(0x01ef, readRegister(run, "SP"));
    }

    @Test
    void rtiEmulationRestoresStatusAndPcFromPageOneStack() throws Exception {
        Run run = start(new byte[] {0x40}); // RTI
        setContextBit(run, "ctx_EF", 1);
        writeRegister(run, "SP", 0x01fc);
        writeRegister(run, "BF", 0);
        writeMemory(run, 0x01fd, new byte[] {(byte) 0xf3}); // Status
        writeMemory(run, 0x01fe, new byte[] {0x45, 0x23}); // PC = $2345

        executeOne(run);

        assertEquals(0x2345, readRegister(run, "PC"));
        assertEquals(0, readRegister(run, "PBR"));
        assertEquals(1, readRegister(run, "NF"));
        assertEquals(1, readRegister(run, "VF"));
        assertEquals(0, readRegister(run, "DF"));
        assertEquals(0, readRegister(run, "IF"));
        assertEquals(1, readRegister(run, "ZF"));
        assertEquals(1, readRegister(run, "CF"));
        assertEquals(0, readRegister(run, "BF"));
        assertEquals(0x01ff, readRegister(run, "SP"));
    }

    @Test
    void rtiEmulationWrapsStackPullsWithinPageOne() throws Exception {
        Run run = start(new byte[] {0x40}); // RTI
        setContextBit(run, "ctx_EF", 1);
        writeRegister(run, "SP", 0x01fe);
        writeRegister(run, "BF", 0);
        writeMemory(run, 0x01ff, new byte[] {(byte) 0xa1}); // N=1, reserved=1, C=1
        writeMemory(run, 0x0100, new byte[] {0x34, 0x12}); // PC = $1234 after wrap
        writeMemory(run, 0x0200, new byte[] {0x78}); // Wrong page must not be read

        executeOne(run);

        assertEquals(0x1234, readRegister(run, "PC"));
        assertEquals(1, readRegister(run, "NF"));
        assertEquals(0, readRegister(run, "VF"));
        assertEquals(1, readRegister(run, "CF"));
        assertEquals(0, readRegister(run, "BF"));
        assertEquals(0x0101, readRegister(run, "SP"));
    }

    @Test
    void brkEmulationPushesOldStatusAndClearsProgramBank() throws Exception {
        Run run = startAt(0x421000, new byte[] {0x00, 0x5a}); // BRK + signature byte
        setContextBit(run, "ctx_EF", 1);
        writeRegister(run, "SP", 0x01f0);
        writeRegister(run, "NF", 1);
        writeRegister(run, "VF", 0);
        writeRegister(run, "DF", 1);
        writeRegister(run, "IF", 0);
        writeRegister(run, "ZF", 1);
        writeRegister(run, "CF", 1);
        writeRegister(run, "BF", 0);
        writeMemory(run, 0xfffe, new byte[] {0x56, 0x34});

        executeOne(run);

        assertEquals(0x3456, readRegister(run, "PC"));
        assertEquals(0, readRegister(run, "PBR"));
        assertEquals(0x01ed, readRegister(run, "SP"));
        assertEquals(0x10, readMemory(run, 0x01f0, 1), "Return PC high byte");
        assertEquals(0x02, readMemory(run, 0x01ef, 1), "Return PC low byte");
        assertEquals(0xbb, readMemory(run, 0x01ee, 1),
            "Stacked status preserves the old D/I flags and sets bits 5 and 4");
        assertEquals(1, readRegister(run, "IF"), "Live I flag is set after stacking");
        assertEquals(0, readRegister(run, "DF"), "Live D flag is cleared after stacking");
    }

    @Test
    void copEmulationPushesStatusAndUsesEmulationVector() throws Exception {
        Run run = startAt(0x421000, new byte[] {0x02, 0x5a}); // COP + signature byte
        setContextBit(run, "ctx_EF", 1);
        writeRegister(run, "SP", 0x01f0);
        writeRegister(run, "NF", 0);
        writeRegister(run, "VF", 1);
        writeRegister(run, "DF", 1);
        writeRegister(run, "IF", 0);
        writeRegister(run, "ZF", 0);
        writeRegister(run, "CF", 0);
        writeRegister(run, "BF", 0);
        writeMemory(run, 0xfff4, new byte[] {0x67, 0x45});

        executeOne(run);

        assertEquals(0x4567, readRegister(run, "PC"));
        assertEquals(0, readRegister(run, "PBR"));
        assertEquals(0x01ed, readRegister(run, "SP"));
        assertEquals(0x10, readMemory(run, 0x01f0, 1), "Return PC high byte");
        assertEquals(0x02, readMemory(run, 0x01ef, 1), "Return PC low byte");
        assertEquals(0x78, readMemory(run, 0x01ee, 1),
            "COP stacks old N/V/D/I/Z/C and forces bits 5 and 4");
        assertEquals(1, readRegister(run, "IF"));
        assertEquals(0, readRegister(run, "DF"));
    }

    @Test
    void cpyEightBitModeUsesOnlyTheLowIndexByte() throws Exception {
        Run run = start(new byte[] {(byte) 0xcc, 0x00, 0x20}); // CPY $2000
        run.emulator().getSharedState().setVar(
            run.space(), DATA_ADDRESS, 2, false, new byte[] {(byte) 0xff, 0x00});
        writeRegister(run, "Y", 0x01fe);
        setContextBit(run, "ctx_XF", 1);

        executeOne(run);

        assertEquals(0, readRegister(run, "CF"),
            "8-bit CPY must compare YLow=$fe with operand=$ff");
        assertEquals(1, readRegister(run, "NF"));
        assertEquals(0, readRegister(run, "ZF"));
    }

    @Test
    void cpySixteenBitModeComparesTheWholeIndexRegister() throws Exception {
        Run run = start(new byte[] {(byte) 0xcc, 0x00, 0x20}); // CPY $2000
        run.emulator().getSharedState().setVar(
            run.space(), DATA_ADDRESS, 2, false, new byte[] {(byte) 0xff, 0x00});
        writeRegister(run, "Y", 0x0100);
        setContextBit(run, "ctx_XF", 0);

        executeOne(run);

        assertEquals(1, readRegister(run, "CF"),
            "16-bit CPY must compare Y=$0100 with operand=$00ff");
        assertEquals(0, readRegister(run, "ZF"));
    }

    @Test
    void xceNativeToNativePreservesIndexHighBytesAndWidths() throws Exception {
        Run run = start(new byte[] {(byte) 0xfb}); // XCE
        writeRegister(run, "X", 0x1234);
        writeRegister(run, "Y", 0x5678);
        writeRegister(run, "CF", 0);
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_MF", 0);
        setContextBit(run, "ctx_XF", 0);

        executeOne(run);

        assertEquals(0x1234, readRegister(run, "X"));
        assertEquals(0x5678, readRegister(run, "Y"));
        assertEquals(0, readRegister(run, "CF"));
    }

    @Test
    void xceNativeToEmulationClearsIndexHighBytes() throws Exception {
        Run run = start(new byte[] {(byte) 0xfb}); // XCE
        writeRegister(run, "X", 0x1234);
        writeRegister(run, "Y", 0x5678);
        writeRegister(run, "CF", 1);
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_MF", 0);
        setContextBit(run, "ctx_XF", 0);

        executeOne(run);

        assertEquals(0x0034, readRegister(run, "X"));
        assertEquals(0x0078, readRegister(run, "Y"));
        assertEquals(0, readRegister(run, "CF"));
        assertEquals(1, readRegister(run, "SPHigh"));
    }

    @Test
    void xceEmulationToNativeExchangesCarryAndEmulationFlag() throws Exception {
        Run run = start(new byte[] {(byte) 0xfb}); // XCE
        writeRegister(run, "X", 0x0034);
        writeRegister(run, "Y", 0x0078);
        writeRegister(run, "CF", 0);
        setContextBit(run, "ctx_EF", 1);
        setContextBit(run, "ctx_MF", 1);
        setContextBit(run, "ctx_XF", 1);

        executeOne(run);

        assertEquals(0x0034, readRegister(run, "X"));
        assertEquals(0x0078, readRegister(run, "Y"));
        assertEquals(1, readRegister(run, "CF"));
    }

    @Test
    void brkEmulationWrapsPageOneStackWhenPushingStatus() throws Exception {
        Run run = startAt(0x421000, new byte[] {0x00, 0x5a}); // BRK + signature byte
        setContextBit(run, "ctx_EF", 1);
        writeRegister(run, "SP", 0x0101);
        writeRegister(run, "NF", 1);
        writeRegister(run, "VF", 0);
        writeRegister(run, "DF", 1);
        writeRegister(run, "IF", 0);
        writeRegister(run, "ZF", 1);
        writeRegister(run, "CF", 1);
        writeRegister(run, "BF", 0);
        writeMemory(run, 0xfffe, new byte[] {0x56, 0x34});
        writeMemory(run, 0x0200, new byte[] {(byte) 0xcc});

        executeOne(run);

        assertEquals(0x3456, readRegister(run, "PC"));
        assertEquals(0, readRegister(run, "PBR"));
        assertEquals(0x01fe, readRegister(run, "SP"));
        assertEquals(0x10, readMemory(run, 0x0101, 1));
        assertEquals(0x02, readMemory(run, 0x0100, 1));
        assertEquals(0xbb, readMemory(run, 0x01ff, 1));
        assertEquals(0xcc, readMemory(run, 0x0200, 1),
            "BRK must wrap its stack writes in emulation mode");
    }

    @Test
    void mvnSixteenBitCopiesCountPlusOneAndUpdatesBanksAndIndexes() throws Exception {
        Run run = start(new byte[] {0x54, 0x02, 0x01}); // MVN dest=$02, src=$01
        setContextBit(run, "ctx_XF", 0);
        writeRegister(run, "X", 0x0010);
        writeRegister(run, "Y", 0x0020);
        writeRegister(run, "C", 0x0002); // A is the byte count minus one
        writeMemory(run, 0x010010, new byte[] {0x11, 0x22, 0x33});

        executeOne(run);

        assertEquals(0x11, readMemory(run, 0x020020, 1));
        assertEquals(0x22, readMemory(run, 0x020021, 1));
        assertEquals(0x33, readMemory(run, 0x020022, 1));
        assertEquals(0x0013, readRegister(run, "X"));
        assertEquals(0x0023, readRegister(run, "Y"));
        assertEquals(0xffff, readRegister(run, "C"));
        assertEquals(0x02, readRegister(run, "DBR"));
    }

    @Test
    void mvpSixteenBitCopiesBackwardsAndUpdatesBanksAndIndexes() throws Exception {
        Run run = start(new byte[] {0x44, 0x02, 0x01}); // MVP dest=$02, src=$01
        setContextBit(run, "ctx_XF", 0);
        writeRegister(run, "X", 0x0012);
        writeRegister(run, "Y", 0x0022);
        writeRegister(run, "C", 0x0002);
        writeMemory(run, 0x010010, new byte[] {0x11, 0x22, 0x33});

        executeOne(run);

        assertEquals(0x11, readMemory(run, 0x020020, 1));
        assertEquals(0x22, readMemory(run, 0x020021, 1));
        assertEquals(0x33, readMemory(run, 0x020022, 1));
        assertEquals(0x000f, readRegister(run, "X"));
        assertEquals(0x001f, readRegister(run, "Y"));
        assertEquals(0xffff, readRegister(run, "C"));
        assertEquals(0x02, readRegister(run, "DBR"));
    }

    @Test
    void mvnEightBitIndexesWrapWithinLowByte() throws Exception {
        Run run = start(new byte[] {0x54, 0x02, 0x01}); // MVN dest=$02, src=$01
        setContextBit(run, "ctx_XF", 1);
        writeRegister(run, "X", 0x00fe);
        writeRegister(run, "Y", 0x00fe);
        writeRegister(run, "C", 0x0002);
        writeMemory(run, 0x0100fe, new byte[] {0x11, 0x22});
        writeMemory(run, 0x010000, new byte[] {0x33});

        executeOne(run);

        assertEquals(0x11, readMemory(run, 0x0200fe, 1));
        assertEquals(0x22, readMemory(run, 0x0200ff, 1));
        assertEquals(0x33, readMemory(run, 0x020000, 1));
        assertEquals(0x0001, readRegister(run, "X"));
        assertEquals(0x0001, readRegister(run, "Y"));
        assertEquals(0xffff, readRegister(run, "C"));
        assertEquals(0x02, readRegister(run, "DBR"));
    }

    @Test
    void adcEightBitDecimalOverflowSetsCarryZeroAndOverflow() throws Exception {
        Run run = start(new byte[] {(byte) 0x6d, 0x00, 0x20}); // ADC $2000
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_MF", 1);
        writeRegister(run, "A", 0x50);
        writeRegister(run, "CF", 0);
        writeRegister(run, "DF", 1);
        writeMemory(run, DATA_ADDRESS, new byte[] {0x50});

        executeOne(run);

        assertEquals(0x00, readRegister(run, "A"));
        assertEquals(1, readRegister(run, "CF"));
        assertEquals(1, readRegister(run, "ZF"));
        assertEquals(1, readRegister(run, "VF"));
        assertEquals(0, readRegister(run, "NF"));
    }

    @Test
    void sbcEightBitDecimalBorrowProducesNinetyNine() throws Exception {
        Run run = start(new byte[] {(byte) 0xed, 0x00, 0x20}); // SBC $2000
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_MF", 1);
        writeRegister(run, "A", 0x00);
        writeRegister(run, "CF", 1);
        writeRegister(run, "DF", 1);
        writeMemory(run, DATA_ADDRESS, new byte[] {0x01});

        executeOne(run);

        assertEquals(0x99, readRegister(run, "A"));
        assertEquals(0, readRegister(run, "CF"));
        assertEquals(0, readRegister(run, "ZF"));
        assertEquals(0, readRegister(run, "VF"));
        assertEquals(1, readRegister(run, "NF"));
    }

    @Test
    void adcSixteenBitDecimalOverflowSetsCarryZeroAndOverflow() throws Exception {
        Run run = start(new byte[] {(byte) 0x6d, 0x00, 0x20}); // ADC $2000
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_MF", 0);
        writeRegister(run, "C", 0x5000);
        writeRegister(run, "CF", 0);
        writeRegister(run, "DF", 1);
        writeMemory(run, DATA_ADDRESS, new byte[] {0x00, 0x50});

        executeOne(run);

        assertEquals(0x0000, readRegister(run, "C"));
        assertEquals(1, readRegister(run, "CF"));
        assertEquals(1, readRegister(run, "ZF"));
        assertEquals(1, readRegister(run, "VF"));
        assertEquals(0, readRegister(run, "NF"));
    }

    @Test
    void sbcSixteenBitDecimalBorrowProducesNineThousandNineHundredNinetyNine() throws Exception {
        Run run = start(new byte[] {(byte) 0xed, 0x00, 0x20}); // SBC $2000
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_MF", 0);
        writeRegister(run, "C", 0x0000);
        writeRegister(run, "CF", 1);
        writeRegister(run, "DF", 1);
        writeMemory(run, DATA_ADDRESS, new byte[] {0x01, 0x00});

        executeOne(run);

        assertEquals(0x9999, readRegister(run, "C"));
        assertEquals(0, readRegister(run, "CF"));
        assertEquals(0, readRegister(run, "ZF"));
        assertEquals(0, readRegister(run, "VF"));
        assertEquals(1, readRegister(run, "NF"));
    }

    @Test
    void xbaExchangesAccumulatorBytes() throws Exception {
        Run run = start(new byte[] {(byte) 0xeb}); // XBA
        writeRegister(run, "A", 0x12);
        writeRegister(run, "B", 0x34);

        executeOne(run);

        assertEquals(0x34, readRegister(run, "A"));
        assertEquals(0x12, readRegister(run, "B"));
        assertEquals(0, readRegister(run, "NF"));
        assertEquals(0, readRegister(run, "ZF"));
    }

    @Test
    void xbaSetsNegativeFromTheNewAccumulatorLowByte() throws Exception {
        Run run = start(new byte[] {(byte) 0xeb}); // XBA
        writeRegister(run, "A", 0x01);
        writeRegister(run, "B", 0x80);

        executeOne(run);

        assertEquals(0x80, readRegister(run, "A"));
        assertEquals(0x01, readRegister(run, "B"));
        assertEquals(1, readRegister(run, "NF"));
        assertEquals(0, readRegister(run, "ZF"));
    }

    @Test
    void xbaSetsZeroWhenTheNewAccumulatorLowByteIsZero() throws Exception {
        Run run = start(new byte[] {(byte) 0xeb}); // XBA
        writeRegister(run, "A", 0x55);
        writeRegister(run, "B", 0x00);

        executeOne(run);

        assertEquals(0x00, readRegister(run, "A"));
        assertEquals(0x55, readRegister(run, "B"));
        assertEquals(0, readRegister(run, "NF"));
        assertEquals(1, readRegister(run, "ZF"));
    }

    @Test
    void cmpAbsoluteUsesUnsignedCarryForZeroLessThanFfff() throws Exception {
        Run run = start(new byte[] {(byte) 0xcd, 0x00, 0x20}); // CMP $2000
        run.emulator().getSharedState().setVar(
            run.space(), DATA_ADDRESS, 2, false, new byte[] {(byte) 0xff, (byte) 0xff});
        writeRegister(run, "C", 0x0000);

        executeOne(run);

        assertEquals(0, readRegister(run, "CF"), "0x0000 is unsigned-less-than 0xffff");
        assertEquals(0, readRegister(run, "ZF"));
    }

    @Test
    void cmpAbsoluteSetsCarryAndZeroForEqualOperands() throws Exception {
        Run run = start(new byte[] {(byte) 0xcd, 0x00, 0x20}); // CMP $2000
        run.emulator().getSharedState().setVar(
            run.space(), DATA_ADDRESS, 2, false, new byte[] {(byte) 0xff, (byte) 0xff});
        writeRegister(run, "C", 0xffff);

        executeOne(run);

        assertEquals(1, readRegister(run, "CF"));
        assertEquals(1, readRegister(run, "ZF"));
    }

    @Test
    void singleStepTestsReadmeVectorMatchesProcessorStateAndMemory() throws Exception {
        JsonObject fixture;
        Path fixturePath = Path.of("src/test/resources/singlestep/3d.e.json");
        try (Reader reader = Files.newBufferedReader(fixturePath)) {
            fixture = JsonParser.parseReader(reader).getAsJsonObject();
        }

        JsonObject initial = fixture.getAsJsonObject("initial");
        JsonObject expected = fixture.getAsJsonObject("final");
        long codeAddress = (initial.get("pbr").getAsLong() << 16)
            | initial.get("pc").getAsLong();
        Run run = startAt(codeAddress);

        for (JsonElement entry : initial.getAsJsonArray("ram")) {
            JsonArray pair = entry.getAsJsonArray();
            writeMemory(run, pair.get(0).getAsLong(),
                new byte[] {(byte) pair.get(1).getAsInt()});
        }

        long status = initial.get("p").getAsLong();
        long emulation = initial.get("e").getAsLong();
        writeRegister(run, "PC", initial.get("pc").getAsLong());
        writeRegister(run, "PBR", initial.get("pbr").getAsLong());
        writeRegister(run, "C", initial.get("a").getAsLong());
        writeRegister(run, "X", initial.get("x").getAsLong());
        writeRegister(run, "Y", initial.get("y").getAsLong());
        writeRegister(run, "DBR", initial.get("dbr").getAsLong());
        writeRegister(run, "DP", initial.get("d").getAsLong());
        writeRegister(run, "SP", initial.get("s").getAsLong());
        writeRegister(run, "NF", (status >> 7) & 1);
        writeRegister(run, "VF", (status >> 6) & 1);
        writeRegister(run, "DF", (status >> 3) & 1);
        writeRegister(run, "IF", (status >> 2) & 1);
        writeRegister(run, "ZF", (status >> 1) & 1);
        writeRegister(run, "CF", status & 1);
        setContextBit(run, "ctx_EF", emulation);
        setContextBit(run, "ctx_MF", emulation == 1 ? 1 : (status >> 5) & 1);
        setContextBit(run, "ctx_XF", emulation == 1 ? 1 : (status >> 4) & 1);
        run.thread().overrideCounter(run.space().getAddress(codeAddress));

        executeOne(run);

        assertEquals(expected.get("pc").getAsLong(), readRegister(run, "PC"), "PC");
        assertEquals(expected.get("pbr").getAsLong(), readRegister(run, "PBR"), "PBR");
        assertEquals(expected.get("a").getAsLong(), readRegister(run, "C"), "Accumulator");
        assertEquals(expected.get("x").getAsLong(), readRegister(run, "X"), "X");
        assertEquals(expected.get("y").getAsLong(), readRegister(run, "Y"), "Y");
        assertEquals(expected.get("dbr").getAsLong(), readRegister(run, "DBR"), "DBR");
        assertEquals(expected.get("d").getAsLong(), readRegister(run, "DP"), "Direct page");
        assertEquals(expected.get("s").getAsLong(), readRegister(run, "SP"), "Stack pointer");
        long expectedStatus = expected.get("p").getAsLong();
        assertEquals((expectedStatus >> 7) & 1, readRegister(run, "NF"), "N");
        assertEquals((expectedStatus >> 6) & 1, readRegister(run, "VF"), "V");
        assertEquals((expectedStatus >> 3) & 1, readRegister(run, "DF"), "D");
        assertEquals((expectedStatus >> 2) & 1, readRegister(run, "IF"), "I");
        assertEquals((expectedStatus >> 1) & 1, readRegister(run, "ZF"), "Z");
        assertEquals(expectedStatus & 1, readRegister(run, "CF"), "C");

        for (JsonElement entry : expected.getAsJsonArray("ram")) {
            JsonArray pair = entry.getAsJsonArray();
            assertEquals(pair.get(1).getAsLong(),
                readMemory(run, pair.get(0).getAsLong(), 1),
                "RAM at 0x" + Long.toHexString(pair.get(0).getAsLong()));
        }
    }


    @Test
    void ldaAbsoluteXCanCarryIntoTheNextDataBank() throws Exception {
        Run run = start(new byte[] {(byte) 0xbd, (byte) 0xff, (byte) 0xff}); // LDA $ffff,X
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_MF", 1);
        setContextBit(run, "ctx_XF", 0);
        writeRegister(run, "DBR", 0x12);
        writeRegister(run, "X", 1);
        writeMemory(run, 0x12ffff, new byte[] {0x11});
        writeMemory(run, 0x130000, new byte[] {0x5a});

        executeOne(run);

        assertEquals(0x5a, readRegister(run, "A"),
            "Absolute indexed addressing carries from DBR:$ffff into the next bank");
    }

    @Test
    void ldaSixteenBitAbsoluteReadCanStraddleDataBankBoundary() throws Exception {
        Run run = start(new byte[] {(byte) 0xad, (byte) 0xff, (byte) 0xff}); // LDA $ffff
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_MF", 0);
        writeRegister(run, "DBR", 0x12);
        writeRegister(run, "C", 0xabcd);
        writeMemory(run, 0x12ffff, new byte[] {0x34});
        writeMemory(run, 0x130000, new byte[] {0x12});

        executeOne(run);

        assertEquals(0x1234, readRegister(run, "C"),
            "The high byte of a 16-bit data access comes from the next bank");
    }

    @Test
    void braAtProgramBankEndWrapsWithinTheSameBank() throws Exception {
        // Both instruction bytes are in this bank; after fetch, PC wraps to $0000.
        Run run = startAt(0x12fffe, new byte[] {(byte) 0x80, 0x00}); // BRA +0
        writeRegister(run, "PC", 0xfffe);
        writeRegister(run, "PBR", 0x12);

        executeOne(run);

        assertEquals(0x0000, readRegister(run, "PC"));
        assertEquals(0x12, readRegister(run, "PBR"),
            "Relative branches wrap the 16-bit PC without carrying into PBR");
        assertEquals(run.space().getAddress(0x120000), run.thread().getCounter(),
            "BRA must target offset $0000 in the original program bank");
    }

    @Test
    void brlAtProgramBankEndWrapsWithinTheSameBank() throws Exception {
        Run run = startAt(0x12fffd, new byte[] {(byte) 0x82, (byte) 0xfe, (byte) 0xff}); // BRL -2
        writeRegister(run, "PC", 0xfffd);
        writeRegister(run, "PBR", 0x12);

        executeOne(run);

        assertEquals(0xfffe, readRegister(run, "PC"));
        assertEquals(0x12, readRegister(run, "PBR"),
            "Relative long branches wrap the 16-bit PC without carrying into PBR");
        assertEquals(run.space().getAddress(0x12fffe), run.thread().getCounter(),
            "BRL must remain in the original program bank after the 16-bit PC wraps");
    }

}
