"""Independent re-verification of the EOBD1260 reverse-engineering claims.

Re-derives every checkable statement from FINDINGS.md / HANDOFF.md directly
from the shipped artifacts (binaries, data files, protocol database) without
reusing the original analysis scripts.  Prints PASS/FAIL per claim.

Run:  python work/verify/verify_claims.py
"""

from __future__ import annotations

import json
import math
import os
import re
import struct
import sys

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORIG = r"C:\eobd-re\orig"

RESULTS = []


def check(claim: str, ok: bool, detail: str = ""):
    RESULTS.append({"claim": claim, "ok": bool(ok), "detail": detail})
    print("%-4s %s%s" % ("PASS" if ok else "FAIL", claim, ("  | " + detail) if detail else ""))


def info(label: str, detail: str):
    print("     %s: %s" % (label, detail))


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in hist if c)


def parse_pe(path: str):
    d = open(path, "rb").read()
    assert d[:2] == b"MZ", "not MZ"
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    assert d[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    coff = e_lfanew + 4
    machine, nsec, _, _, _, optsize, _ = struct.unpack_from("<HHIIIHH", d, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    numrva = struct.unpack_from("<I", d, opt + 92)[0]
    dd = opt + 96
    imp_rva, _ = struct.unpack_from("<II", d, dd + 8)
    secs = []
    sh = opt + optsize
    for i in range(nsec):
        b = sh + i * 40
        name = d[b:b + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, b + 8)
        secs.append((name, vaddr, vsize, raddr, rsize))

    def rva2off(rva):
        for name, vaddr, vsize, raddr, rsize in secs:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return raddr + (rva - vaddr)
        return None

    def cstr(off):
        return d[off:d.index(b"\0", off)].decode("latin1")

    imports = {}
    off = rva2off(imp_rva)
    while off:
        desc = d[off:off + 20]
        if len(desc) < 20 or desc == b"\0" * 20:
            break
        oft, ts, fc, name_rva, first_thunk = struct.unpack("<IIIII", desc)
        if name_rva == 0:
            break
        dll = cstr(rva2off(name_rva))
        funcs = []
        toff = rva2off(oft or first_thunk)
        j = 0
        while True:
            t = struct.unpack_from("<I", d, toff + j * 4)[0]
            if t == 0:
                break
            funcs.append("ord#%d" % (t & 0xFFFF) if t & 0x80000000 else cstr(rva2off(t) + 2))
            j += 1
        imports[dll.lower()] = funcs
        off += 20
    return {"magic": magic, "machine": machine, "sections": secs, "imports": imports}


def parse_auto(path: str):
    raw = open(path, "rb").read().decode("latin1")
    recs, cur = [], None
    for ln in raw.split("\r\n"):
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            if cur:
                recs.append(cur)
            cur = {"name": s[1:].strip(), "ids": []}
            continue
        if cur is None:
            continue
        if s.startswith("id="):
            cur["ids"] = [int(x) for x in re.findall(r"\d+", s[3:])]
    if cur:
        recs.append(cur)
    return recs


def gal_decode(p: str) -> bytes:
    return bytes(b ^ 0x1C for b in open(p, "rb").read())


# ------------------------------------------------------------------ checks ---
print("=" * 78)
print("EOBD1260 — независимая перепроверка (raw artifacts)")
print("=" * 78)

print("\n--- §1 состав пакета ---")
inv = {"EOBD1260.exe": 4455936, "winmap.dll": 724992, "Gcheck.dll": 2351104,
       "multiROM.dll": 122880, "FTD2XX.dll": 81920, "auto.dll": 43327,
       "auto2.dll": 43323, "k.dat": 48, "apertura.dat": 1064}
for fn, exp in inv.items():
    p = os.path.join(PROJ, fn)
    ok = os.path.isfile(p) and os.path.getsize(p) == exp
    check("файл %-14s размер %d" % (fn, exp), ok,
          "" if ok else "actual=%s" % (os.path.getsize(p) if os.path.isfile(p) else "missing"))
n_chk = len(os.listdir(os.path.join(PROJ, "chk")))
check("chk/ — 148 файлов", n_chk == 148, "actual=%d" % n_chk)
exts = {}
for f in os.listdir(os.path.join(PROJ, "chk")):
    e = os.path.splitext(f)[1].lower()
    exts[e] = exts.get(e, 0) + 1
info("chk/ расширения", str(exts))
for fn in ("auto.dll", "auto2.dll"):
    check("%s — не PE (не начинается с MZ), текст" % fn,
          open(os.path.join(PROJ, fn), "rb").read(2) != b"MZ")

print("\n--- §2 транспорт FTDI ---")
pe = parse_pe(os.path.join(PROJ, "EOBD1260.exe"))
imp = pe["imports"]
info("sections", ",".join(s[0] for s in pe["sections"]))
info("импортируемых DLL", "%d: %s" % (len(imp), ", ".join(sorted(imp))))
claim_list = ["FT_OpenEx", "FT_Close", "FT_Read", "FT_Write", "FT_SetBaudRate",
              "FT_SetDataCharacteristics", "FT_SetTimeouts", "FT_Purge",
              "FT_SetRts", "FT_ClrRts", "FT_SetDtr", "FT_ClrDtr", "FT_ListDevices"]
ft = next((d for d in imp if "ftd2xx" in d), None)
if ft is None:
    check("импорт из ftd2xx.dll присутствует", False, "DLL: %s" % sorted(imp))
else:
    got = imp[ft]
    check("ftd2xx.dll — ровно 13 функций", len(got) == 13, "actual=%d" % len(got))
    check("ftd2xx.dll — состав совпадает со списком", sorted(got) == sorted(claim_list),
          "diff %s" % sorted(set(got) ^ set(claim_list)))
    check("FT_SetBitMode отсутствует", "FT_SetBitMode" not in got)

print("\n--- §5 apertura.dat ---")
ap = open(os.path.join(PROJ, "apertura.dat"), "rb").read().decode("latin1")
sections, cur = [], None
for ln in ap.split("\r\n"):
    s = ln.strip()
    if not s:
        continue
    if s.startswith("#"):
        cur = {"name": s, "base": None, "recs": []}
        sections.append(cur)
    elif cur is not None:
        if cur["base"] is None:
            cur["base"] = int(s, 16)
        else:
            cur["recs"].append(s)
got_ap = [(s["name"], s["base"], len(s["recs"]),
           len(s["recs"][0]) // 2 if s["recs"] else 0) for s in sections]
exp_ap = [("#swap", 0, 16, 8), ("#siemens1", 0, 24, 8), ("#siemens2", 0, 6, 8),
          ("#boschme7", 0, 1, 8), ("#EDC16", 0x6000, 4, 8), ("#EDC16", 0, 3, 5), ("#ME9", 0, 1, 8)]
info("секции", str(got_ap))
check("7 секций с ожидаемыми базами/счётчиками/длинами", got_ap == exp_ap, "exp=%s" % str(exp_ap))

print("\n--- §6 защита ---")
kdat = [x for x in open(os.path.join(PROJ, "k.dat"), "rb").read().decode("latin1").split()
        if re.fullmatch(r"[0-9A-Fa-f]{8}", x)]
check("k.dat — 5 hex-значений (накопленные хеши)", len(kdat) == 5, str(kdat))
exe = open(os.path.join(PROJ, "EOBD1260.exe"), "rb").read()
winmap = open(os.path.join(PROJ, "winmap.dll"), "rb").read()
gc = open(os.path.join(PROJ, "Gcheck.dll"), "rb").read()
for probe, blob, label in [
        (b"qkBr", winmap, "HASP vendor-строка в winmap.dll"),
        (b"smartchk.exe", exe, "smartchk.exe (анти-отладка)"),
        (b"procdump.exe", exe, "procdump.exe"), (b"pdumpnt.exe", exe, "pdumpnt.exe"),
        (b"td32.exe", exe, "td32.exe"), (b"IsDebuggerPresent", exe, "IsDebuggerPresent"),
        (b"HaspDecrypt", gc, "экспорт HaspDecrypt (Gcheck.dll)"),
        (b"HaspEncrypt", gc, "экспорт HaspEncrypt (Gcheck.dll)"),
        (b"classic_key_info", winmap, "classic_key_info в winmap.dll"),
        (b"hasp_login", winmap, "hasp_login в winmap.dll")]:
    check("строка %s" % label, probe in blob)
gpe = parse_pe(os.path.join(PROJ, "Gcheck.dll"))
for name, vaddr, vsize, raddr, rsize in gpe["sections"]:
    if name == ".protect":
        e = entropy(gc[raddr:raddr + min(rsize, 1 << 20)])
        info(".protect", "vsize=%#x entropy(1MB)=%.3f" % (vsize, e))
        check(".protect: ~1.46 МБ, энтропия ~8.0", abs(e - 8.0) < 0.05 and vsize > 1_400_000)
        break

print("\n--- §8.1 chk/* (заявлено: зашифрованы, байты 0-6 const, байт7 0x92..0x9B, ноль 0x00) ---")
chkdir = os.path.join(PROJ, "chk")
files = sorted(os.listdir(chkdir))
heads, byte7, zeros, entropies = set(), set(), 0, []
for f in files:
    d = open(os.path.join(chkdir, f), "rb").read()
    heads.add(d[:7]); byte7.add(d[7]); zeros += d.count(0); entropies.append(entropy(d))
info("первые 7 байт", " ".join("%02X" % b for b in next(iter(heads))) + " (вариантов: %d)" % len(heads))
info("байт 7", " ".join("%02X" % b for b in sorted(byte7)))
info("нулевых байт", str(zeros))
info("энтропия", "%.3f..%.3f" % (min(entropies), max(entropies)))
check("байты 0–6 одинаковы = 44 8B C3 D1 AD 8D 4C",
      len(heads) == 1 and next(iter(heads)) == bytes.fromhex("448BC3D1AD8D4C"))
check("байт 7 в 0x92..0x9B", all(0x92 <= b <= 0x9B for b in byte7))
check("ноль байтов 0x00", zeros == 0)
allbin = exe + winmap + gc
check("имена chk-файлов не встречаются в бинарях",
      all(os.path.splitext(f)[0].encode("latin1") not in allbin for f in files))
check("строка '.chk' отсутствует в EXE", b".chk" not in exe)
info("вхождения 'chk' в EXE", str(exe.count(b"chk")) + " (все — smartchk: %d)" % exe.count(b"smartchk.exe"))

print("\n--- §8.2 EOBD2_LOG/*.gal (заявлено: зашифрованы, энтропия 7.95) ---")
logdir = os.path.join(PROJ, "EOBD2_LOG")
gals = sorted(f for f in os.listdir(logdir) if f.lower().endswith(".gal"))
sizes = sorted(os.path.getsize(os.path.join(logdir, f)) for f in gals)
info("файлов", "%d, размеры %d..%d" % (len(gals), sizes[0], sizes[-1]))
ents = sorted(((entropy(open(os.path.join(logdir, f), "rb").read()), f) for f in gals), reverse=True)
info("топ-3 по энтропии", ["%s=%.3f" % (f, e) for e, f in ents[:3]])
stub = gal_decode(os.path.join(logdir, "_eobd2_1021539.gal"))
check("XOR 0x1C: 16-байтовый лог даёт кадр KWP2000 82 12 F1 10 85 1A + 0xFF padding",
      stub == bytes.fromhex("8212F110851A") + b"\xff" * 10, stub.hex(" "))
vag = gal_decode(os.path.join(logdir, "_eobd2_3521629.gal"))
check("XOR 0x1C: VAG-лог даёт 82 12 F3 10 85 1C и тексты идентификации",
      vag.startswith(bytes.fromhex("8212F310851C")) and b"G4AS01M0" in vag)
check("заявление «энтропия 7.95» не воспроизводится; максимум %.3f" % ents[0][0],
      abs(ents[0][0] - 7.95) > 0.02, "см. VERIFICATION.md §gal")
big = [e for e, f in ents if os.path.getsize(os.path.join(logdir, f)) > 1000]
check("текстовые логи (6.2..7.2) и один near-uniform (%.3f) — два класса" % max(big),
      min(big) < 6.5 and max(big) > 7.9, str(["%.3f" % x for x in sorted(big)]))

print("\n--- профили ЭБУ: raw auto.dll/auto2.dll vs база ---")
recs = parse_auto(os.path.join(PROJ, "auto.dll")) + parse_auto(os.path.join(PROJ, "auto2.dll"))
check("320 записей профилей (160+160)", len(recs) == 320, "actual=%d" % len(recs))
db = json.load(open(os.path.join(PROJ, "05-spec", "protocols-database.json"), encoding="utf-8"))
byid = {p["protocol_id"]: p for p in db["protocols"]}
rawname = {}
for r in recs:
    rawname.setdefault(r["name"], set()).update(r["ids"])
dbfirst = {}
for p in db["protocols"]:
    for pr in p["ecu_profiles"]:
        dbfirst.setdefault(pr["profile"], set()).add(p["protocol_id"])
only_raw = set(rawname) - set(dbfirst)
mismatch = [(n, sorted(rawname[n]), sorted(dbfirst[n])) for n in set(rawname) & set(dbfirst)
            if rawname[n] != dbfirst[n]]
info("профилей", "raw=%d db=%d, id-конфликтов=%d, нет в базе=%d" % (
    len(rawname), len(dbfirst), len(mismatch), len(only_raw)))
info("профили без протокола", str(sorted((n, sorted(rawname[n])) for n in only_raw)))
check("каждое имя профиля из raw сопоставлено протоколу с тем же id", not mismatch and not only_raw,
      "orphans=%s" % sorted(only_raw))
ids = {p["protocol_id"] for p in db["protocols"]}
missing_ids = [i for i in range(183) if i not in ids]
info("id без протокольного класса", str(missing_ids))

print("\n--- §3.4 spot-check id → VMT → профиль ---")
spot = {0: ("0x00621174", "BMW330D"), 1: ("0x00621510", "BMWMSS52M3E46"),
        2: ("0x006214BC", "BMWMSS50M3E36"), 11: ("0x00623B48", "RENAULTSIRIUS32"),
        16: ("0x00621FA8", "FIATME73H4KWP2000")}
for pid, (vmt, prof) in spot.items():
    p = byid.get(pid)
    names = [x["profile"] for x in (p.get("ecu_profiles") or [])] if p else []
    check("id=%d VMT=%s профиль %s" % (pid, vmt, prof),
          bool(p) and (p.get("vmt") or "").lower() == vmt.lower() and prof in names,
          "db: vmt=%s profs=%s" % (p.get("vmt") if p else None, names[:3]))

print("\n--- база 05-spec: инварианты ---")
check("178 протоколов", len(ids) == 178, "actual=%d" % len(ids))
check("id в 0..182", min(ids) == 0 and max(ids) == 182)
full = [p for p in db["protocols"] if len(p["primitives"]) == 7]
check("177/178 с полным набором 7 примитивов (id=182 — fallback)",
      len(full) == 177 and {p["protocol_id"] for p in db["protocols"] if len(p["primitives"]) != 7} == {182})
vmts = [int(p["vmt"], 16) for p in db["protocols"] if p["protocol_id"] != 182 and p.get("vmt")]
check("VMT всех 177 классов в .rdata 0x6206FC..0x62423C",
      all(0x6206FC <= v <= 0x62423C for v in vmts), "min=%#x max=%#x" % (min(vmts), max(vmts)))
check("VMT id=182 вне диапазона (fallback-ветка)", int(byid[182]["vmt"], 16) == 0x6202F4)
funcs_with_frames = {k: v for k, v in db["functions"].items() if v.get("frames")}
check("956 функций с кадрами", len(funcs_with_frames) == 956, "actual=%d" % len(funcs_with_frames))
uniq_frames = sum(len(v["frames"]) for v in funcs_with_frames.values())
sum_pc = sum(p["frame_count"] for p in db["protocols"])
check("кадров: 3126 уникальных (в 956 функциях) / 3257 в сумме по протоколам",
      uniq_frames == 3126 and sum_pc == 3257,
      "uniq=%d sum(frame_count)=%d" % (uniq_frames, sum_pc))
withfr = [p for p in db["protocols"] if p["frame_count"] > 0]
check("169 протоколов с распознанными кадрами", len(withfr) == 169, "actual=%d" % len(withfr))
bad_len = sum(1 for v in funcs_with_frames.values() for fr in v["frames"] if fr["len"] != len(fr["bytes"]))
bad_known = sum(1 for v in funcs_with_frames.values() for fr in v["frames"]
                if fr["known"] != sum(1 for b in fr["bytes"] if b is not None))
check("len(template)==len и known==число констант во всех кадрах", bad_len == 0 and bad_known == 0,
      "len_viol=%d known_viol=%d" % (bad_len, bad_known))
push_len = sum(1 for v in funcs_with_frames.values() for fr in v["frames"]
               if fr.get("len_src") == "push")
check("длина кадров из push-аргумента (len_src=push) у >95%% кадров",
      push_len > 0.95 * uniq_frames, "push=%d of %d" % (push_len, uniq_frames))
refs = set()
for p in db["protocols"]:
    for pr in p["primitives"]:
        refs.add(pr["function"])
missing_refs = refs - set(db["functions"])
info("ссылки примитивов", "unique=%d, с кадрами=%d, без кадров=%d" % (
    len(refs), len(refs & set(db["functions"])), len(missing_refs)))

print("\n--- §4 кадры-примеры (после уточнения) ---")


def frames_of(pid):
    out = []
    for pr in byid[pid]["primitives"]:
        out += db["functions"].get(pr["function"], {}).get("frames", [])
    return out


def has_subseq(frames, pat, strict=False):
    """Has a frame containing pat.  strict=False: None acts as wildcard;
    strict=True: every matched byte must be a non-None constant equal to pat."""
    for f in frames:
        t = f["bytes"]
        for i in range(len(t) - len(pat) + 1):
            seg = t[i:i + len(pat)]
            if strict:
                if all(b is not None and b == p for b, p in zip(seg, pat)):
                    return True
            elif all(b is None or b == p for b, p in zip(seg, pat)):
                return True
    return False


f0 = frames_of(0)
check("id=0 seed-key: 27 01 (RequestSeed)", has_subseq(f0, [0x27, 0x01]))
check("id=0 seed-key: 27 02 42 4D 57 17 (ключ 'BMW')", has_subseq(f0, [0x27, 0x02, 0x42, 0x4D, 0x57, 0x17]))
check("id=0 close-write: B8 12 F1 03 30 EB 01 82",
      has_subseq(frames_of(0), [0xB8, 0x12, 0xF1, 0x03, 0x30, 0xEB, 0x01, 0x82]))
check("id=0 erase: 09 31 02 08 ... 06", has_subseq(f0, [0x09, 0x31, 0x02, 0x08]))
f16 = frames_of(16)
check("id=16 init: 02 1A 98 00 (подтверждено псевдокодом sub_49B700)",
      has_subseq(f16, [0x02, 0x1A, 0x98, 0x00]))
check("FINDINGS-пример 'id=16 → 82 12 F1 10 85 1A' НЕ подтверждён: у id=16 такого кадра нет",
      not has_subseq(f16, [0x82, 0x12, 0xF1, 0x10, 0x85, 0x1A], strict=True))
attributed = sorted(p["protocol_id"] for p in db["protocols"]
                    if has_subseq(frames_of(p["protocol_id"]), [0x82, 0x12, 0xF1, 0x10, 0x85, 0x1A],
                                  strict=True))
info("82 12 F1 10 85 1A принадлежит протоколам", str(attributed))
check("82 12 F1 10 85 1A: надмножество {19,26,49,59,61,67,74,75} (дизельные EDC15)",
      {19, 26, 49, 59, 61, 67, 74, 75} <= set(attributed))
check("82 12 F1 10 85 1A: полный набор 12 протоколов (v2 дополнил 62/64/72/163; "
      "для id=62 кадр подтверждён в sub_4E3090)",
      set(attributed) == {19, 26, 49, 59, 61, 62, 64, 67, 72, 74, 75, 163},
      "actual=%s" % attributed)

print("\n--- AUDIT-2 §2: кадры id=0 после пересборки экстрактором v2 (exact) ---")


def has_exact(frames, pat):
    """strict all-constant byte-identical frame of the same length"""
    for f in frames:
        if f["len"] == len(pat) and all(b is not None and b == p
                                         for b, p in zip(f["bytes"], pat)):
            return True
    return False


check("erase: 8-байтовый кадр восстановлен (был потерян)",
      has_exact(f0, [0xB8, 0x12, 0xF1, 0x03, 0x30, 0xEB, 0x01, 0x82]))
check("erase: ветвь 0F/68 присутствует (не подменена дубликатом)",
      has_exact(f0, [0xB8, 0x12, 0xF1, 0x09, 0x31, 0x02, 0x0F, 0x00, 0x00,
                     0x06, 0x00, 0x00, 0x00, 0x68]))
check("erase: ветвь 08/6F присутствует",
      has_exact(f0, [0xB8, 0x12, 0xF1, 0x09, 0x31, 0x02, 0x08, 0x00, 0x00,
                     0x06, 0x00, 0x00, 0x00, 0x6F]))
check("write-block: байт 5 = 0F, а не 68 (слияние ветвей устранено)",
      has_exact(f0, [0xB8, 0x12, 0xF1, 0x09, 0x34, 0x0F, 0x00, 0x00, 0x06,
                     0x00, 0x00, 0xC0, 0x00, 0xAF]))
check("write-block: ADDR-цикл — len=14 из push, байты адреса рантайм + варианты",
      any(f["len"] == 14 and f["len_src"] == "push"
          and f["bytes"][:5] == [0xB8, 0x12, 0xF1, 0x09, 0x34]
          and f["bytes"][5] is None and f["variants"] for f in frames_of(0)))
cw = db["functions"].get("sub_43EC50", {}).get("frames", [])
check("close-write: ровно 8 байт (было len=17)",
      any(f["len"] == 8 and f["bytes"] == [0xB8, 0x12, 0xF1, 0x03, 0x30,
                                           0xEB, 0x01, 0x82] for f in cw))
check("нет кадров len<=0",
      all(f["len"] > 0 for v in funcs_with_frames.values() for f in v["frames"]))

print("\n--- реплика: запрет live для кадров без подтверждённой длины ---")
try:
    import importlib.util
    src_dir = os.path.join(PROJ, "10-replica", "src")
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    spec = importlib.util.spec_from_file_location(
        "replica_loader", os.path.join(src_dir, "loader.py"))
    rl = importlib.util.module_from_spec(spec)
    sys.modules["replica_loader"] = rl  # dataclasses needs the module registered
    spec.loader.exec_module(rl)
    f_push = rl.Frame(0, 1, [0xAA], 1, len_src="push")
    f_ext = rl.Frame(1, 1, [0xAA], 1, len_src="extent")
    check("Frame.len_confirmed: push=True, extent=False",
          f_push.len_confirmed and not f_ext.len_confirmed)
    cli = rl.KLineClient(None, verbose=False)
    prim = rl.Primitive(12, "erase", "unittest", 1, [f_ext])
    out = cli.run_primitive(prim, dry_run=False)  # live path must refuse
    check("run_primitive(live) отказывает кадру len_src=extent", out == [])
except Exception as exc:
    check("реплика: защита неподтверждённых кадров", False, repr(exc))

fails = [r for r in RESULTS if not r["ok"]]
print("\n" + "=" * 78)
print("ИТОГО: %d проверок, PASS=%d, FAIL=%d" % (len(RESULTS), len(RESULTS) - len(fails), len(fails)))
for r in fails:
    print("  FAIL: %s | %s" % (r["claim"], r["detail"]))
out = os.path.join(PROJ, "work", "verify", "verify-results.json")
json.dump(RESULTS, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print("результаты: %s" % out)
sys.exit(1 if fails else 0)
