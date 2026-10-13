"""Headless IDA export: functions, strings, imports, segments.

Run:  idat.exe -A -S"<this script>" -L<log> <target>
Outputs land in <target>.ida-out/ next to the analysed file, and the .i64
database is kept so later runs load the database instead of re-analysing.
"""
import json
import os
import time

import ida_auto
import ida_entry
import ida_funcs
import ida_nalt
import ida_segment
import idautils
import idc


def main():
    target = idc.get_input_file_path()
    d = target + ".ida-out"
    os.makedirs(d, exist_ok=True)
    base = os.path.basename(target)

    t0 = time.time()
    ida_auto.auto_wait()
    ana_s = time.time() - t0

    segs = []
    for s in idautils.Segments():
        sg = ida_segment.getseg(s)
        segs.append({
            "name": ida_segment.get_segm_name(sg),
            "start": sg.start_ea,
            "end": sg.end_ea,
            "perm": sg.perm,
            "bitness": sg.bitness,
        })

    funcs = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        funcs.append({
            "ea": ea,
            "name": idc.get_func_name(ea),
            "size": (f.end_ea - f.start_ea) if f else 0,
        })

    strings = []
    for s in idautils.Strings():
        try:
            val = str(s)
        except Exception:
            continue
        strings.append({"ea": s.ea, "len": s.length, "type": s.strtype, "val": val})

    imports = []
    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i)

        def cb(ea, name, ordinal, mod=mod):
            imports.append({"module": mod, "ea": ea, "name": name or ("#%d" % ordinal), "ord": ordinal})
            return True

        ida_nalt.enum_import_names(i, cb)

    entries = []
    for k in range(ida_entry.get_entry_qty()):
        ordn = ida_entry.get_entry_ordinal(k)
        entries.append({"ord": ordn, "ea": ida_entry.get_entry(ordn), "name": ida_entry.get_entry_name(ordn)})

    def dump(name, obj):
        with open(os.path.join(d, base + "-" + name + ".json"), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=1)

    dump("funcs", funcs)
    dump("strings", strings)
    dump("segs", segs)
    dump("imports", imports)
    dump("entries", entries)

    with open(os.path.join(d, "SUMMARY.txt"), "w", encoding="utf-8") as fh:
        fh.write("analysis_seconds=%.1f\nfuncs=%d\nstrings=%d\nimports=%d\nsegs=%d\n" %
                 (ana_s, len(funcs), len(strings), len(imports), len(segs)))

    print("[ida_export] %.1fs funcs=%d strings=%d imports=%d segs=%d" %
          (ana_s, len(funcs), len(strings), len(imports), len(segs)))

    # NOTE: never save_database(input_path) - IDA would pack the DB into the binary
    idc.qexit(0)


main()
