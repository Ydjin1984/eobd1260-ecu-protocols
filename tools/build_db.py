"""Build the final EOBD1260 protocol database.

Joins:
  proto-map.json      id -> constructor / VMT / method slots
  switch-blocks.json  id -> case block calls
  dump/frames.json    method -> extracted byte frames
  auto.dll/auto2.dll  ECU profiles (name, ids, vehicles)  [parsed earlier]
  Informazioni.txt    ECU identification table

Produces (into the project's 05-spec/):
  protocols-database.json   machine readable
  PROTOKOLY.md              human readable, per protocol id
"""
import json
import os
import re

FUNCS = {}
HERE = r"C:\eobd-re"
PROJ = r"C:\Users\lex66\OneDrive\Рабочий стол\EOBD1260"
OUT = os.path.join(PROJ, "05-spec")
os.makedirs(OUT, exist_ok=True)

PRIM_OFFSETS = [8, 12, 16, 20, 24, 28, 32]
# names guessed from the orchestrator + error strings seen in the binary
PRIM_NAMES = {
    8: "init/write-setup",
    12: "erase",
    16: "write-block",
    20: "close-write",
    24: "aux/verify",
    28: "aux2",
    32: "seed-key",
}


def load(path, default=None):
    try:
        return json.load(open(path, encoding='utf-8'))
    except Exception:
        return default if default is not None else {}


def parse_profiles():
    """re-parse auto.dll/auto2.dll into profile records"""
    recs = []
    for f in ("auto.dll", "auto2.dll"):
        p = os.path.join(HERE, "orig", f)
        if not os.path.exists(p):
            continue
        raw = open(p, 'rb').read().decode('latin1')
        cur = None
        for ln in raw.split('\r\n'):
            s = ln.strip()
            if not s:
                continue
            if s.startswith('#'):
                if cur:
                    recs.append(cur)
                cur = {"profile": s[1:].strip(), "ids": [], "notes": [], "apps": [], "src": f}
                continue
            if cur is None:
                continue
            if s.startswith('id='):
                cur["ids"] = [int(x) for x in re.findall(r'\d+', s)]
            elif s.startswith("'"):
                cur["notes"].append(s[1:].strip())
            elif set(s) <= set('-') and len(s) > 3:
                continue
            else:
                cur["apps"].append(s)
        if cur:
            recs.append(cur)
    return recs


def parse_informazioni():
    p = os.path.join(HERE, "orig", "Informazioni.txt")
    if not os.path.exists(p):
        return []
    out = []
    for ln in open(p, encoding='latin1'):
        s = ln.rstrip('\r\n')
        if not s.strip():
            continue
        parts = [x.strip() for x in s.split(',')]
        if len(parts) < 4:
            continue
        tail = [x for x in parts if x]
        pid = None
        for cand in reversed(parts):
            if cand.isdigit():
                pid = int(cand)
                break
        out.append({"name": parts[0], "code": parts[1],
                    "fields": parts[2:], "protocol_id": pid, "raw": s})
    return out


def frames_for(fn_stem, frames_db):
    for k, v in frames_db.items():
        if k.startswith(fn_stem + "__") or k == fn_stem:
            return v.get("frames", []), k
    return None, None


def fmt_frame(fr):
    if not fr:
        return ""
    bs = ' '.join('%02X' % b if b is not None else '--' for b in fr['bytes'])
    return bs


def main():
    pm = load(os.path.join(HERE, "proto-map.json"), [])
    frames_db = load(os.path.join(HERE, "dump", "frames.json"), {})
    profiles = parse_profiles()
    info = parse_informazioni()

    by_id = {}
    for prof in profiles:
        for pid in prof["ids"]:
            by_id.setdefault(pid, []).append(prof)

    global FUNCS
    db = []
    for rec in pm:
        pid = rec["id"]
        slots = {s['off']: s for s in (rec.get("slots") or [])}
        prims = []
        for off in PRIM_OFFSETS:
            s = slots.get(off)
            if not s or not s.get('name'):
                continue
            frs, stem = frames_for(s['name'], frames_db)
            if frs:
                FUNCS.setdefault(s['name'], {"ea": s['ea'], "frames": frs})
            prims.append({
                "offset": off,
                "role": PRIM_NAMES[off],
                "function": s['name'],
                "ea": s['ea'],
                "nframes": len(frs or []),
            })
        entry = {
            "protocol_id": pid,
            "constructor": rec.get("ctor"),
            "vmt": rec.get("vmt"),
            "primitives": prims,
            "frame_count": sum(p["nframes"] for p in prims),
            "ecu_profiles": [
                {"profile": p["profile"], "apps": p["apps"][:12], "notes": p["notes"]}
                for p in by_id.get(pid, [])
            ],
        }
        db.append(entry)

    db.sort(key=lambda e: e["protocol_id"])
    with open(os.path.join(OUT, "protocols-database.json"), "w", encoding="utf-8") as fh:
        json.dump({"protocols": db, "functions": FUNCS,
                   "informazioni": info, "profile_table": profiles},
                  fh, indent=1, ensure_ascii=False)

    # ---- markdown ----
    with open(os.path.join(OUT, "PROTOKOLY.md"), "w", encoding="utf-8") as fh:
        fh.write("# EOBD1260 — база протоколов ЭБУ\n\n")
        fh.write("Извлечено статическим анализом `EOBD1260.exe` (IDA Pro 9.2, Hex-Rays).\n\n")
        fh.write("- Карта `id -> класс протокола` взята из фабрики `sub_5703B0` (switch по id).\n")
        fh.write("- Каждый класс — 7 протокольных методов (VMT+8..+32) + общий транспорт (VMT+0x4C).\n")
        fh.write("- Кадры извлечены из ассемблера методов: константные байты показаны,\n")
        fh.write("  `--` = байт вычисляется в рантайме (адрес, seed/key, счётчик).\n\n")
        fh.write("## Сводка\n\n")
        fh.write("| id | VMT | методов | кадров | профили ЭБУ |\n|---|---|---|---|---|\n")
        for e in db:
            profs = ", ".join(p["profile"] for p in e["ecu_profiles"]) or "—"
            fh.write("| %d | `%s` | %d | %d | %s |\n" % (
                e["protocol_id"], e["vmt"], len(e["primitives"]), e["frame_count"], profs))
        fh.write("\n## Кадры по протоколам\n\n")
        for e in db:
            if not e["frame_count"]:
                continue
            fh.write("### id=%d  (VMT `%s`)\n\n" % (e["protocol_id"], e["vmt"]))
            for p in e["ecu_profiles"]:
                fh.write("- профиль `%s`: %s\n" % (
                    p["profile"], "; ".join(p["apps"][:6])))
            fh.write("\n")
            for pr in e["primitives"]:
                frs_l = (FUNCS.get(pr["function"]) or {}).get("frames") or []
                if not frs_l:
                    continue
                fh.write("**%s** (`%s`, VMT+%d)\n\n" % (pr["role"], pr["function"], pr["offset"]))
                for i, fr in enumerate(frs_l):
                    fh.write("- кадр %d (%d байт, известно %d): `%s`\n" %
                             (i, fr["len"], fr["known"], fmt_frame(fr)))
                fh.write("\n")
            fh.write("\n")

    print("[db] protocols=%d with frames=%d profiles=%d informazioni=%d" % (
        len(db), sum(1 for e in db if e["frame_count"]), len(profiles), len(info)))
    print("[db] wrote %s" % OUT)


main()
