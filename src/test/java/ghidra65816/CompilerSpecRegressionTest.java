package ghidra65816;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

/** Smoke tests for the 65816 compiler specification. */
class CompilerSpecRegressionTest {
    private static Language language;

    @BeforeAll
    static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assertNotNull(installDir, "GHIDRA_INSTALL_DIR must be set by the test workflow");

        String externalModules = System.getenv("GHIDRA_EXTERNAL_MODULES");
        assertNotNull(externalModules,
            "GHIDRA_EXTERNAL_MODULES must point to the compiled language module");
        System.setProperty("ghidra.external.modules", externalModules);

        if (!Application.isInitialized()) {
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)),
                new HeadlessGhidraApplicationConfiguration());
        }

        language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("65816:LE:16:default"));
    }

    @Test
    void defaultCompilerSpecLoads() {
        CompilerSpec compilerSpec = language.getDefaultCompilerSpec();

        assertNotNull(compilerSpec);
        assertNotNull(compilerSpec.getDefaultCallingConvention());
        assertEquals("__unknowncall",
            compilerSpec.getDefaultCallingConvention().getName());
    }
}
