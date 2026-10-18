package ghidra65816;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import java.util.concurrent.TimeUnit;

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
        PcodeEmulator emulator = new PcodeEmulator(language);
        AddressSpace space = language.getDefaultSpace();
        emulator.getSharedState().setVar(space, CODE_ADDRESS, code.length, false, code);
        PcodeThread<byte[]> thread = emulator.newThread();
        thread.overrideCounter(space.getAddress(CODE_ADDRESS));
        thread.overrideContextWithDefault();
        Run run = new Run(emulator, thread, space);
        writeRegister(run, "DBR", 0);
        return run;
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
}
