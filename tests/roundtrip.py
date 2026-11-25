"""Check byte-exact compression/decompression across SREP stream formats."""
import random
import subprocess
import tempfile
from pathlib import Path

binary = Path(__file__).resolve().parents[1] / "bin" / "srep"
rng = random.Random(0)
noise = bytes(rng.randrange(256) for _ in range(64 * 1024))
cases = {"empty": b"", "mixed": noise + b"SREP round-trip\n" * 32768 + noise}
modes = {"-m3o": 1, "-m5o": 2, "-m3f": 3, "-m3": 4}
with tempfile.TemporaryDirectory(prefix="srep-test-") as directory:
    root = Path(directory)
    for name, data in cases.items():
        source = root / name
        source.write_bytes(data)
        for mode in modes:
            archive = root / (name + mode + ".srep")
            output = root / (name + mode + ".out")
            for args in ((mode, str(source), str(archive)),
                         ("-d", str(archive), str(output))):
                result = subprocess.run([str(binary), *args], capture_output=True)
                if result.returncode:
                    raise RuntimeError(result.stderr.decode(errors="replace"))
            version = int.from_bytes(archive.read_bytes()[8:12], "little") & 255
            if version != modes[mode]:
                raise AssertionError(f"Unexpected stream version: {mode}: {version}")
            if output.read_bytes() != data:
                raise AssertionError(f"Round-trip mismatch: {name} {mode}")
            print(f"PASS {name} {mode}")
