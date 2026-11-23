// Flag XCE instructions whose fall-through Carry setter is bypassed by a conditional jump.
// @category 65816
import java.io.PrintStream;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

public class Flag65816XceCarryJoins extends GhidraScript {
    private static final String CATEGORY = "65816 XCE Carry";

    private static boolean changesCarry(Instruction instruction) throws Exception {
        String mnemonic = instruction.getMnemonicString();
        if ("CLC".equals(mnemonic) || "SEC".equals(mnemonic)) {
            return true;
        }
        if ("REP".equals(mnemonic) || "SEP".equals(mnemonic)) {
            byte[] bytes = instruction.getBytes();
            return bytes.length > 1 && (bytes[1] & 1) != 0;
        }
        return false;
    }

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguage().getLanguageID().toString().startsWith("65816:")) {
            throw new IllegalArgumentException("This script requires the 65816 language");
        }

        String[] args = getScriptArgs();
        PrintStream out = args.length > 0 ? new PrintStream(args[0]) : null;
        try {
            Listing listing = currentProgram.getListing();
            BookmarkManager bookmarks = currentProgram.getBookmarkManager();
            int warnings = 0;

            for (Instruction xce : listing.getInstructions(true)) {
                monitor.checkCancelled();
                if (!"XCE".equals(xce.getMnemonicString())) {
                    continue;
                }
                Address target = xce.getAddress();
                Instruction setter = listing.getInstructionBefore(target);
                if (setter == null || !target.equals(setter.getFallThrough())
                        || !changesCarry(setter)) {
                    continue;
                }

                for (Reference reference : currentProgram.getReferenceManager()
                        .getReferencesTo(target)) {
                    if (!reference.getReferenceType().isJump()
                            || !reference.getReferenceType().isConditional()
                            || reference.getFromAddress().compareTo(setter.getAddress()) >= 0) {
                        continue;
                    }
                    Instruction branch = listing.getInstructionAt(reference.getFromAddress());
                    if (branch == null || !branch.getFlowType().isConditional()) {
                        continue;
                    }

                    String note = "Conditional " + branch.getMnemonicString() + " at "
                        + branch.getAddress() + " bypasses " + setter.getMnemonicString()
                        + " at " + setter.getAddress()
                        + "; Carry and instruction widths after XCE may be path-dependent.";
                    bookmarks.setBookmark(target, BookmarkType.WARNING, CATEGORY, note);
                    Bookmark saved = bookmarks.getBookmark(target, BookmarkType.WARNING, CATEGORY);
                    if (saved == null) {
                        throw new IllegalStateException("XCE Carry warning bookmark not saved");
                    }
                    warnings++;
                    if (out != null) {
                        out.printf("XCE_JOIN|%06x|%06x|%s%n", target.getOffset(),
                            branch.getAddress().getOffset(), setter.getMnemonicString());
                    }
                    break;
                }
            }

            println("Potential XCE Carry joins: " + warnings);
        }
        finally {
            if (out != null) {
                out.close();
            }
        }
    }
}
