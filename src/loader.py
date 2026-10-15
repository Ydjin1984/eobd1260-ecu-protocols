"""EOBD1260 protocol database access + K-line client skeleton.

The database in ../05-spec/protocols-database.json is produced by static
analysis of the original binary.  For every ECU profile it names the protocol
class (`protocol_id`), the seven protocol primitives and the byte frames those
primitives transmit.  Bytes shown as `null` in the database are the ones the
original computes at runtime (addresses, seed/key answers, counters) - those
are what a caller has to fill in.

Key structures from the original (verified addresses in EOBD1260.exe):

    transport send      VMT+0x4C   send(self, buf, len, timeout_lo, timeout_hi)
    transport write     sub_574F00 -> FT_Write
    transport read      sub_574F90 -> FT_Read
    xor checksum        sub_4018C0
    delay               sub_5811F0(double milliseconds)
    factory (id->class) sub_5703B0 (switch over protocol id)
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from ftdi_d2xx import FtdiDevice, FtdiError, xor_checksum, sum_checksum

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_db():
    """Locate protocols-database.json across the three layouts this code ships in:

    public repo   src/loader.py          -> ../spec/protocols-database.json
    archive repo  replica/src/loader.py  -> ../../analysis/05-spec/protocols-database.json
    project       .../10-replica/src/    -> ../../05-spec/protocols-database.json
    """
    rels = [
        os.path.join("..", "spec", "protocols-database.json"),
        os.path.join("..", "..", "analysis", "05-spec", "protocols-database.json"),
        os.path.join("..", "..", "05-spec", "protocols-database.json"),
        os.path.join("..", "analysis", "05-spec", "protocols-database.json"),
        os.path.join("..", "protocols-database.json"),
    ]
    candidates = []
    env = os.environ.get("EOBD_DB")
    if env:
        candidates.append(env)
    candidates += [os.path.normpath(os.path.join(HERE, r)) for r in rels]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[-1]


DB_PATH = _find_db()

KNOWN = object()


@dataclass
class Frame:
    index: int
    length: int
    template: list  # ints, or None where the original used a runtime value
    known: int
    len_src: str = "extent"   # "push" = length taken from the sent argument
    variants: dict = field(default_factory=dict)

    @property
    def len_confirmed(self) -> bool:
        """True when the frame length comes from the `push imm` before the
        transport call (extractor v2).  Frames extracted with the write-extent
        fallback may be truncated and must not be transmitted blindly."""
        return self.len_src == "push"

    def render(self, **values) -> bytes:
        """Fill the runtime slots.

        `values` may contain either "b<i>" per byte position or `data=` with a
        bytes object for the tail.  Unfilled unknown slots raise, so a caller
        cannot silently send garbage.
        """
        out = bytearray()
        for i, b in enumerate(self.template):
            if b is not None:
                out.append(b)
                continue
            key = "b%d" % i
            if key in values:
                out.append(values[key] & 0xFF)
            elif "data" in values and i >= values.get("data_offset", 0):
                out.append(values["data"][i - values.get("data_offset", 0)])
            else:
                raise ValueError("frame %d: byte %d needs a value" % (self.index, i))
        return bytes(out)

    def describe(self) -> str:
        return " ".join("%02X" % b if b is not None else "--" for b in self.template)


@dataclass
class Primitive:
    offset: int
    role: str
    function: str
    nframes: int
    frames: list = field(default_factory=list)


@dataclass
class Protocol:
    protocol_id: int
    vmt: str
    constructor: str
    profiles: list
    primitives: list

    def primitive(self, role: str) -> Primitive | None:
        for p in self.primitives:
            if p.role == role:
                return p
        return None


class ProtocolDatabase:
    def __init__(self, path: str = DB_PATH):
        raw = json.load(open(path, encoding="utf-8"))
        self.functions = raw["functions"]
        self.protocols = {}
        for p in raw["protocols"]:
            prims = []
            for pr in p["primitives"]:
                fr = (self.functions.get(pr["function"]) or {}).get("frames") or []
                prims.append(Primitive(pr["offset"], pr["role"], pr["function"],
                                       pr["nframes"], [self._frame(i, f) for i, f in enumerate(fr)]))
            self.protocols[p["protocol_id"]] = Protocol(
                p["protocol_id"], p.get("vmt"), p.get("constructor"),
                p.get("ecu_profiles") or [], prims)
        # profile name -> protocol id
        self.by_profile = {}
        for pid, proto in self.protocols.items():
            for prof in proto.profiles:
                self.by_profile.setdefault(prof["profile"].lower(), pid)

    @staticmethod
    def _frame(i, f):
        return Frame(f["send_index"], f["len"], f["bytes"], f["known"],
                     len_src=f.get("len_src", "extent"),
                     variants=f.get("variants") or {})

    def get(self, protocol_id: int) -> Protocol:
        return self.protocols[protocol_id]

    def find_profile(self, needle: str):
        needle = needle.lower()
        hits = []
        for pid, proto in self.protocols.items():
            for prof in proto.profiles:
                if needle in prof["profile"].lower():
                    hits.append((pid, prof))
        return hits

    def summary(self):
        lines = ["id  VMT         methods frames  profiles"]
        for pid in sorted(self.protocols):
            p = self.protocols[pid]
            names = ", ".join(x["profile"] for x in p.profiles[:3])
            lines.append("%-3d %-11s %-7d %-7d %s" % (
                pid, p.vmt or "-", len(p.primitives),
                sum(len(x.frames) for x in p.primitives), names))
        return "\n".join(lines)


# --- K-line client ----------------------------------------------------------
class KLineClient:
    """Speaks the extracted protocol steps over an FTDI D2XX cable.

    This is deliberately conservative: read-only operations first, every write
    step gated, and nothing is sent that is not in the extracted database.
    """

    def __init__(self, dev: FtdiDevice, baud: int = 10400, echo: bool = True,
                 verbose: bool = True):
        self.dev = dev
        self.baud = baud
        self.echo = echo        # K-line adapters often echo what we send
        self.verbose = verbose
        self.log = []

    def configure(self, baud: int | None = None, parity: int = 0):
        self.baud = baud or self.baud
        self.dev.set_baudrate(self.baud)
        self.dev.set_line(8, 0, parity)
        self.dev.set_timeouts(50, 50)
        self.dev.purge()

    def send(self, frame: bytes, wait_ms: int = 100) -> bytes:
        self.dev.purge()
        self.dev.write(frame)
        self._record("TX", frame)
        resp = self.dev.read_exact(256, wait_ms)
        if self.echo and resp[: len(frame)] == frame:
            resp = resp[len(frame):]
        self._record("RX", resp)
        return resp

    def _record(self, direction: str, data: bytes):
        entry = (direction, data.hex())
        self.log.append(entry)
        if self.verbose:
            print("  %s %s" % (direction, " ".join("%02X" % b for b in data)))

    # -- protocol driven helpers -------------------------------------------
    def run_primitive(self, prim: Primitive, wait_ms: int = 200, dry_run: bool = True,
                      allow_unconfirmed: bool = False):
        """Send every frame of a protocol step in order.

        `dry_run` prints the traffic instead of driving the cable, which is the
        sane default while a protocol has not been verified on a bench ECU.

        Frames whose length was not taken from the original `push imm` (the
        extractor had to fall back to the write extent) are refused for live
        transmission unless `allow_unconfirmed` is set: a truncated frame can
        silently put an ECU into an undefined state (AUDIT-2 §3).
        """
        out = []
        for fr in prim.frames:
            if not dry_run and not fr.len_confirmed and not allow_unconfirmed:
                print("  [refused] frame %d: length %d not confirmed "
                      "(len_src=%s); pass allow_unconfirmed to override"
                      % (fr.index, fr.length, fr.len_src))
                continue
            try:
                raw = fr.render()
            except ValueError:
                if self.verbose:
                    print("  [skip] frame %d needs runtime bytes: %s"
                          % (fr.index, fr.describe()))
                continue
            if dry_run:
                if self.verbose:
                    print("  [dry] would send %s%s"
                          % (" ".join("%02X" % b for b in raw),
                             "" if fr.len_confirmed else "   (len unconfirmed!)"))
                out.append((raw, b""))
                continue
            resp = self.send(raw, wait_ms)
            out.append((raw, resp))
            time.sleep(0.05)
        return out


def _main():
    import argparse

    ap = argparse.ArgumentParser(description="EOBD1260 replica loader")
    ap.add_argument("--db", default=DB_PATH)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-devices", help="enumerate FTDI devices")
    sp = sub.add_parser("protocols", help="list protocol ids")
    sp.add_argument("--profile", help="filter by ECU profile substring")
    sp = sub.add_parser("show", help="show one protocol's frames")
    sp.add_argument("id", type=int)
    sp = sub.add_parser("probe", help="send a protocol step over the cable")
    sp.add_argument("id", type=int)
    sp.add_argument("--step", default="seed-key")
    sp.add_argument("--serial", help="FTDI serial number")
    sp.add_argument("--baud", type=int, default=10400)
    sp.add_argument("--live", action="store_true", help="actually transmit")
    sp.add_argument("--allow-unconfirmed", action="store_true",
                    help="permit live frames whose length was not confirmed "
                         "by the extractor (see AUDIT-2 §3)")

    args = ap.parse_args()

    if args.cmd == "list-devices":
        print("\n".join(FtdiDevice.describe()) or "(none)")
        return

    db = ProtocolDatabase(args.db)

    if args.cmd == "protocols":
        if args.profile:
            for pid, prof in db.find_profile(args.profile):
                print("id=%-4d %s  ->  %s" % (pid, prof["profile"], "; ".join(prof["apps"][:4])))
        else:
            print(db.summary())
        return

    if args.cmd == "show":
        p = db.get(args.id)
        print("protocol id=%d vmt=%s" % (p.protocol_id, p.vmt))
        for prof in p.profiles:
            print("  profile %s: %s" % (prof["profile"], "; ".join(prof["apps"][:6])))
        for prim in p.primitives:
            print("\n%s  (%s, VMT+%d)" % (prim.role, prim.function, prim.offset))
            for fr in prim.frames:
                print("   frame %-2d len=%-3d known=%-3d %-6s  %s"
                      % (fr.index, fr.length, fr.known,
                         fr.len_src, fr.describe()))
                if fr.variants and fr.known != fr.length:
                    print("            runtime variants: %s"
                          % {k: v for k, v in sorted(fr.variants.items())})
        return

    if args.cmd == "probe":
        p = db.get(args.id)
        prim = p.primitive(args.step)
        if not prim:
            print("protocol %d has no step %r; available: %s"
                  % (args.id, args.step, [x.role for x in p.primitives]))
            return
        if args.live:
            unconf = [fr for fr in prim.frames if not fr.len_confirmed]
            if unconf and not args.allow_unconfirmed:
                print("refusing --live: %d frame(s) without a confirmed length"
                      % len(unconf))
                for fr in unconf:
                    print("   frame %-2d len=%-4d len_src=%s"
                          % (fr.index, fr.length, fr.len_src))
                print("A frame extracted from the write extent may be truncated;"
                      " pass --allow-unconfirmed to override (AUDIT-2 §3).")
                return
            dev = FtdiDevice().open(serial=args.serial)
            cli = KLineClient(dev, baud=args.baud)
            cli.configure()
        else:
            cli = KLineClient(None)
            print("(dry run - pass --live to transmit)")
        cli.run_primitive(prim, dry_run=not args.live,
                          allow_unconfirmed=args.allow_unconfirmed)
        return


if __name__ == "__main__":
    _main()
