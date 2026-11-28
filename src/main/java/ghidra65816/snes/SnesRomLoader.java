package ghidra65816.snes;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;

public class SnesRomLoader extends AbstractProgramWrapperLoader {
    @Override
    public String getName() {
        return "SNES ROM";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider file) throws IOException {
        if (SnesCartridge.detect(file) == null) {
            return List.of();
        }
        return List.of(new LoadSpec(this, 0,
            new LanguageCompilerSpecPair("65816:LE:16:default", "default"), true));
    }

    @Override
    protected void loadProgramInto(Program program, ImporterSettings settings) throws IOException {
        throw new IOException("SNES ROM import requires a new program");
    }

    @Override
    protected void load(Program program, ImporterSettings settings) throws IOException, CancelledException {
        var file = settings.provider();
        var monitor = settings.monitor();
        monitor.checkCancelled();
        var cart = SnesCartridge.detect(file);
        if (cart == null) {
            throw new IOException("Unsupported or ambiguous SNES cartridge header or geometry");
        }
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var mem = program.getMemory();
        var windows = SnesMemoryMap.plan(cart);
        try (InputStream in = file.getInputStream(0)) {
            FileBytes bytes = mem.createFileBytes(file.getName(), 0, file.length(), in, monitor);
            for (var window : windows) {
                monitor.checkCancelled();
                var start = space.getAddress(window.start());
                String name = "%s_%06X".formatted(window.ram() ? "WRAM" : "ROM", window.start());
                MemoryBlock block = switch (window.kind()) {
                    case ROM -> mem.createInitializedBlock(name, start, bytes,
                        cart.prefix() + window.source(), window.size(), false);
                    case WRAM -> mem.createUninitializedBlock(name, start, window.size(), false);
                    case ALIAS -> mem.createByteMappedBlock(name, start,
                        space.getAddress(window.source()), window.size(), false);
                };
                block.setPermissions(true, window.ram(), !window.ram());
            }
            var vector = space.getAddress(0xfffc);
            var target = space.getAddress(Short.toUnsignedInt(mem.getShort(vector)));
            if (target.getOffset() != cart.reset()) {
                throw new IOException("Mapped reset vector differs from cartridge header");
            }
            program.getListing().createData(vector, WordDataType.dataType);
            program.getReferenceManager().addMemoryReference(vector, target, RefType.DATA, SourceType.IMPORTED, 0);
            program.getSymbolTable().createLabel(target, "RESET", SourceType.IMPORTED);
            program.getSymbolTable().addExternalEntryPoint(target);
            var context = program.getProgramContext();
            for (String name : List.of("ctx_EF", "ctx_MF", "ctx_XF")) {
                context.setValue(context.getRegister(name), target, target, BigInteger.ONE);
            }
            var decode = new DisassembleCommand(target, new AddressSet(target), false);
            if (!decode.applyTo(program, monitor) || program.getListing().getInstructionAt(target) == null) {
                monitor.checkCancelled();
                throw new IOException("Cannot decode instruction at SNES reset vector " + target);
            }
            monitor.checkCancelled();
        }
        catch (CancelledException e) {
            throw e;
        }
        catch (UsrException e) {
            throw new IOException("Cannot create SNES cartridge map: " + e.getMessage(), e);
        }
    }
}
