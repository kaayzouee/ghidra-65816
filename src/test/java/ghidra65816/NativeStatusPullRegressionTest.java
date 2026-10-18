package ghidra65816;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

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

/** Runtime coverage for native PLP/RTI status-dependent index cleanup. */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class NativeStatusPullRegressionTest {
    private static final long CODE_ADDRESS = 0x1000;
    private static Language language;

    private record Run(PcodeEmulator emulator, PcodeThread<byte[]> thread, AddressSpace space) {}

    @BeforeAll
    static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assertNotNull(installDir, "GHIDRA_INSTALL_DIR must be set by CI");

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
        return new Run(emulator, thread, space);
    }

    private static void writeRegister(Run run, String name, long value) {
        Register register = language.getRegister(name);
        assertNotNull(register, "Missing 65816 register: " + name);
        PcodeArithmetic<byte[]> arithmetic = run.emulator().getArithmetic();
        run.thread().getState().setVar(
            register, arithmetic.fromConst(value, register.getNumBytes()));
    }

    private static long readRegister(Run run, String name) {
        Register register = language.getRegister(name);
        assertNotNull(register, "Missing 65816 register: " + name);
        PcodeArithmetic<byte[]> arithmetic = run.emulator().getArithmetic();
        return arithmetic.toLong(
            run.thread().getState().getVar(register, Reason.INSPECT), Purpose.INSPECT);
    }

    private static void setContextBit(Run run, String name, long value) {
        Register contextBit = language.getRegister(name);
        assertNotNull(contextBit, "Missing 65816 context field: " + name);
        RegisterValue context = run.thread().getContext()
            .assign(contextBit, BigInteger.valueOf(value));
        run.thread().overrideContext(context);
    }

    private static void writeMemory(Run run, long address, byte[] bytes) {
        run.emulator().getSharedState().setVar(
            run.space(), address, bytes.length, false, bytes);
    }

    private static void executeOne(Run run) throws Exception {
        run.thread().stepInstruction();
    }

    @Test
    void nativePlpClearsIndexHighBytesFromPulledXFlag() throws Exception {
        Run run = start(new byte[] {0x28}); // PLP
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_XF", 0);
        writeRegister(run, "SP", 0x01ee);
        writeRegister(run, "X", 0x1234);
        writeRegister(run, "Y", 0x5678);
        writeMemory(run, 0x01ef, new byte[] {(byte) 0x91}); // N=1, X=1, C=1

        executeOne(run);

        assertEquals(0x0034, readRegister(run, "X"));
        assertEquals(0x0078, readRegister(run, "Y"));
        assertEquals(1, readRegister(run, "NF"));
        assertEquals(1, readRegister(run, "CF"));
        assertEquals(0x01ef, readRegister(run, "SP"));
    }

    @Test
    void nativePlpPreservesIndexHighBytesWhenPulledXFlagIsClear() throws Exception {
        Run run = start(new byte[] {0x28}); // PLP
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_XF", 0);
        writeRegister(run, "SP", 0x01ee);
        writeRegister(run, "X", 0x1234);
        writeRegister(run, "Y", 0x5678);
        writeMemory(run, 0x01ef, new byte[] {0x01}); // X=0, C=1

        executeOne(run);

        assertEquals(0x1234, readRegister(run, "X"));
        assertEquals(0x5678, readRegister(run, "Y"));
        assertEquals(1, readRegister(run, "CF"));
        assertEquals(0x01ef, readRegister(run, "SP"));
    }

    @Test
    void nativeRtiUsesPulledXFlagAndRestoresPcAndBank() throws Exception {
        Run run = start(new byte[] {0x40}); // RTI
        setContextBit(run, "ctx_EF", 0);
        setContextBit(run, "ctx_XF", 0);
        writeRegister(run, "SP", 0x01fc);
        writeRegister(run, "X", 0x1234);
        writeRegister(run, "Y", 0x5678);
        writeMemory(run, 0x01fd, new byte[] {0x10}); // X=1
        writeMemory(run, 0x01fe, new byte[] {0x34, 0x12}); // PC = $1234
        writeMemory(run, 0x0200, new byte[] {0x7a}); // PBR = $7a

        executeOne(run);

        assertEquals(0x0034, readRegister(run, "X"));
        assertEquals(0x0078, readRegister(run, "Y"));
        assertEquals(0x1234, readRegister(run, "PC"));
        assertEquals(0x7a, readRegister(run, "PBR"));
        assertEquals(0x0200, readRegister(run, "SP"));
    }
}
