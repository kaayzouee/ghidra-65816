"""Exercise auto-discovery and raw import in an installation containing the extension ZIP."""
import os
from pathlib import Path
import subprocess
import tempfile

from ghidra_paths import analyze_headless

ROOT = Path(__file__).resolve().parents[2]


def fixture(folder, hi, prefix, size):
    rom = bytearray(size)
    header = 0xffc0 if hi else 0x7fc0
    rom[header:header + 21] = b"SYNTHETIC SNES".ljust(21)
    rom[header + 21] = 0x31 if hi else 0x20
    rom[header + 23] = size.bit_length() - 11
    rom[header + 60:header + 62] = b"\x00\x80"
    code = 0x8000 if hi else 0
    rom[code:code + 6] = bytes.fromhex("a9 42 4c 00 80 ea")
    rom[-1] = 0x72
    if size > 0x10000:
        rom[0x10000] = 0x5a
    path = folder / f"{'hi' if hi else 'lo'}-{prefix}-{size}.bin"
    path.write_bytes(bytes(prefix) + rom)
    return path


def run():
    launcher = analyze_headless(Path(os.environ["GHIDRA_INSTALL_DIR"]))
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        roms = folder / "roms"
        roms.mkdir()
        for hi in (False, True):
            fixture(roms, hi, 0, 0x10000 if hi else 0x8000)
            fixture(roms, hi, 512, 0x20000)
            fixture(roms, hi, 0, 0x400000)
        for mode in ("snes", "analysis", "raw"):
            input_path = {"raw": roms / "lo-0-32768.bin", "analysis": roms / "hi-512-131072.bin"}.get(mode, roms)
            flags = [] if mode == "analysis" else ["-noanalysis"]
            if mode == "raw":
                flags += ["-loader", "BinaryLoader", "-processor", "65816:LE:16:default"]
            result = subprocess.run(
                [launcher, str(folder), mode, "-import", str(input_path),
                 *flags, "-scriptPath", str(ROOT / "tests"),
                 "-postScript", "G65816SnesCheck.java", mode, str(folder),
                 "-deleteProject"], check=False)
            result.check_returncode()
            for image in ([input_path] if input_path.is_file() else roms.iterdir()):
                marker = folder / (image.name + ("." + mode))
                if not marker.is_file():
                    raise AssertionError(f"Missing headless verification for {image.name}")


if __name__ == "__main__":
    run()
