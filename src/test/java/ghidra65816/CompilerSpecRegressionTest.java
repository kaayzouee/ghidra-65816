package ghidra65816;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.File;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.pcode.Varnode;
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

    private boolean containsRegister(Varnode[] varnodes, String expectedName) {
        for (Varnode varnode : varnodes) {
            var register = language.getRegister(varnode.getAddress(), varnode.getSize());
            if (register != null && register.getName().equals(expectedName)) {
                return true;
            }
        }
        return false;
    }

    private void assertHasRegister(Varnode[] varnodes, String registerName) {
        assertTrue(containsRegister(varnodes, registerName),
            "Expected register " + registerName + " in " + java.util.Arrays.toString(varnodes));
    }

    @Test
    void nearAndFarModelsDeclareCallerClobbersAndPreservedState() {
        CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
        String[] callerClobbered = {
            "X", "Y", "DP", "DBR", "NF", "VF", "DF", "IF", "ZF", "CF", "BF"
        };

        for (String conventionName : new String[] { "__near", "__far" }) {
            PrototypeModel model = compilerSpec.getCallingConvention(conventionName);
            assertNotNull(model, "Missing calling convention " + conventionName);

            Varnode[] unaffected = model.getUnaffectedList();
            Varnode[] killedByCall = model.getKilledByCallList();

            // RTS and RTL both restore the caller's program bank. The optional
            // prototypes therefore preserve both the stack pointer and PBR.
            assertHasRegister(unaffected, "SP");
            assertHasRegister(unaffected, "PBR");
            assertFalse(containsRegister(killedByCall, "SP"),
                conventionName + " must not mark SP caller-clobbered");
            assertFalse(containsRegister(killedByCall, "PBR"),
                conventionName + " must not mark PBR caller-clobbered");

            for (String registerName : callerClobbered) {
                assertHasRegister(killedByCall, registerName);
            }
        }
    }

    @Test
    void nearAndFarModelsDescribeTheirReturnAddresses() {
        CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
        PrototypeModel near = compilerSpec.getCallingConvention("__near");
        PrototypeModel far = compilerSpec.getCallingConvention("__far");

        assertNotNull(near);
        assertNotNull(far);
        assertEquals("__unknowncall",
            compilerSpec.getDefaultCallingConvention().getName());

        assertEquals(2, near.getExtrapop());
        assertEquals(2, near.getStackshift());
        assertEquals(3, far.getExtrapop());
        assertEquals(3, far.getStackshift());

        Varnode[] nearReturnAddress = near.getReturnAddress();
        Varnode[] farReturnAddress = far.getReturnAddress();
        assertNotNull(nearReturnAddress);
        assertNotNull(farReturnAddress);
        assertEquals(1, nearReturnAddress.length);
        assertEquals(1, farReturnAddress.length);
        assertEquals("stack", nearReturnAddress[0].getAddress().getAddressSpace().getName());
        assertEquals("stack", farReturnAddress[0].getAddress().getAddressSpace().getName());
        assertEquals(1, nearReturnAddress[0].getOffset());
        assertEquals(1, farReturnAddress[0].getOffset());
        assertEquals(2, nearReturnAddress[0].getSize());
        assertEquals(3, farReturnAddress[0].getSize());
    }
}
