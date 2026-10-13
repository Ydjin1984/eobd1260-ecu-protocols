"""Build the definitive EOBD1260 protocol map.

Input : dump/switch-blocks.json (case -> [helper, constructor]) produced from
        the factory pseudocode.
Task  : for every constructor find the VMT it installs, then list that VMT's
        method slots; also recover the Delphi class name when present.

Output: proto-map.json  (one record per protocol id)
"""
import json
import os
import re

import ida_bytes
import ida_funcs
import ida_segment
import idautils
import idc

VMT_LO, VMT_HI = 0x620000, 0x625000
MAX_SLOTS = 40


def is_code_ptr(v):
    sg = ida_segment.getseg(v)
    return bool(sg and (sg.perm & ida_segment.SEGPERM_EXEC))


def fname(ea):
    f = ida_funcs.get_func(ea)
    if f and f.start_ea == ea:
        return ida_funcs.get_func_name(ea)
    return None


def shortstring_at(ea):
    if not ea or ea < 0x1000:
        return None
    ln = ida_bytes.get_byte(ea)
    if not (1 < ln < 64):
        return None
    bs = ida_bytes.get_bytes(ea + 1, ln)
    if not bs or not all(32 <= c < 127 for c in bs):
        return None
    return bs.decode("latin1")


def _scan_for_vmt(f):
    found = []
    ea = f.start_ea
    while ea < f.end_ea:
        for x in idautils.XrefsFrom(ea, 0):
            if VMT_LO <= x.to < VMT_HI:
                found.append(x.to)
        ne = idc.next_head(ea, f.end_ea)
        if ne == idc.BADADDR or ne <= ea:
            break
        ea = ne
    return sorted(set(found))


def vmt_for_function(fea, depth=0):
    """find the VMT this function installs.

    Many constructors are thin wrappers (`return sub_XXXXXX(this);`), so when a
    scan finds nothing we follow one tail-call level.
    """
    f = ida_funcs.get_func(fea)
    if not f:
        return None
    found = _scan_for_vmt(f)
    if found:
        return found[0]
    if depth >= 2:
        return None
    # follow tail-calls / direct calls (wrappers are a handful of bytes)
    ea = f.start_ea
    while ea < f.end_ea:
        for x in idautils.CodeRefsFrom(ea, 1):
            g = ida_funcs.get_func(x)
            if g and g.start_ea != f.start_ea:
                v = vmt_for_function(g.start_ea, depth + 1)
                if v is not None:
                    return v
        ne = idc.next_head(ea, f.end_ea)
        if ne == idc.BADADDR or ne <= ea:
            break
        ea = ne
    return None


def class_name_for_vmt(vmt):
    # Delphi keeps vmtClassName at a negative offset; scan a window instead of
    # trusting one offset.
    for off in range(4, 200, 4):
        ptr = ida_bytes.get_dword(vmt - off)
        nm = shortstring_at(ptr)
        if nm and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,40}", nm):
            return nm
    return None


def slots_of(vmt):
    out = []
    i = 0
    while i < MAX_SLOTS * 4:
        v = ida_bytes.get_dword(vmt + i)
        if is_code_ptr(v):
            out.append({"off": i, "ea": "0x%08X" % v, "name": fname(v) or ("sub_%X" % v)})
        elif v == 0:
            out.append({"off": i, "ea": None, "name": None})
        else:
            break
        i += 4
    return out


def main():
    blocks = json.load(open(r"C:\eobd-re\dump\switch-blocks.json", encoding="utf-8"))
    # cache class->vmt for every candidate in the range
    cache = {}
    out = []
    for k, calls in sorted(blocks.items(), key=lambda kv: int(kv[0])):
        ctor = calls[-1]
        ea = idc.get_name_ea_simple(ctor)
        vmt = vmt_for_function(ea) if ea != idc.BADADDR else None
        rec = {"id": int(k), "ctor": ctor}
        if vmt is not None:
            if vmt not in cache:
                cache[vmt] = {"class_name": class_name_for_vmt(vmt), "slots": slots_of(vmt)}
            rec["vmt"] = "0x%08X" % vmt
            rec["class_name"] = cache[vmt]["class_name"]
            rec["slots"] = cache[vmt]["slots"]
        out.append(rec)

    json.dump(out, open(r"C:\eobd-re\proto-map.json", "w", encoding="utf-8"), indent=1)
    got = sum(1 for r in out if r.get("vmt"))
    print("[map] ids=%d with VMT=%d" % (len(out), got))
    for r in out[:12]:
        print("   id=%-4s %s vmt=%s name=%s slots=%s" % (
            r["id"], r["ctor"], r.get("vmt"), r.get("class_name"),
            len(r.get("slots") or [])))
    idc.qexit(0)


main()
