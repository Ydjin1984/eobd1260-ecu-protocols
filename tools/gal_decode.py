"""Decode EOBD1260 session logs (EOBD2_LOG/_eobd2_*.gal).

The vendor tool writes its session logs obfuscated with a single-byte XOR
key 0x1C applied to the whole file.  After decoding, the logs contain real
K-line traffic (ISO 14230 / KWP2000 frames) and ECU identification blocks:
a decoded log shows frames like `82 12 F1 10 85 1A` (StartDiagnosticSession)
and strings such as `0281010161... SmartEDG15C-5.1` or VINs (Opel
`W0L0TGF08X...`).

Evidence collected during the verification pass (docs/VERIFICATION.md §2):
  * 16-byte "empty" logs decode to `82 12 F1 10 85 1A` + 0xFF padding;
  * text logs land in 6.2..7.2 byte entropy, one binary-heavy log at 8.0;
  * the "repeats of E3 / 2C" reported earlier in the ciphertext are simply
    0xFF ^ 0x1C (padding) and '0' ^ 0x1C (digits).

Usage:
    python gal_decode.py FILE.gal [out.bin]     single file -> file or hexdump
    python gal_decode.py FILE.gal --strings     print printable runs only
    python gal_decode.py DIR [outdir]           every *.gal in DIR

No dependencies beyond the standard library.
"""

from __future__ import annotations

import os
import re
import sys

KEY = 0x1C


def decode(data: bytes) -> bytes:
    return bytes(b ^ KEY for b in data)


def strings(data: bytes, minlen: int = 8):
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)


def hexdump(data: bytes, limit: int = 256):
    for off in range(0, min(limit, len(data)), 16):
        chunk = data[off:off + 16]
        yield "%06X  %-47s  %s" % (
            off,
            " ".join("%02X" % b for b in chunk),
            "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
        )


def do_file(path: str, out: str | None, only_strings: bool):
    data = open(path, "rb").read()
    dec = decode(data)
    if only_strings:
        for s in strings(dec):
            print(s.decode("latin1"))
        return
    if out:
        open(out, "wb").write(dec)
        print("wrote %s (%d bytes)" % (out, len(dec)))
        return
    print("--- %s (%d bytes) decoded ---" % (os.path.basename(path), len(dec)))
    for line in hexdump(dec):
        print(line)
    found = strings(dec)
    if found:
        print("--- printable runs ---")
        for s in found[:40]:
            print(s.decode("latin1"))


def do_dir(src: str, outdir: str | None):
    files = sorted(f for f in os.listdir(src) if f.lower().endswith(".gal"))
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    for name in files:
        data = open(os.path.join(src, name), "rb").read()
        dec = decode(data)
        if outdir:
            open(os.path.join(outdir, name), "wb").write(dec)
        print("%-28s %8d -> %8d bytes, %d printable runs" % (
            name, len(data), len(dec), len(strings(dec))))
    if not files:
        print("(no *.gal files in %s)" % src)


def main(argv):
    args = [a for a in argv[1:] if a != "--strings"]
    only_strings = "--strings" in argv[1:]
    if not args:
        print(__doc__.strip())
        return 2
    target = args[0]
    out = args[1] if len(args) > 1 else None
    if os.path.isdir(target):
        do_dir(target, out)
    else:
        do_file(target, out, only_strings)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
