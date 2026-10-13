"""Parse the EOBD1260 vehicle/ECU profile database (auto.dll, auto2.dll).

The files are plain CRLF text, not PE images. Layout:

    \\r\\n
    #PROFILE_ID                     <- profile key (used as  chk/<key>.chk )
    id=179                          <- numeric ECU id(s), may be "id=86,90"
    \\r\\n
    ' NOTE LINE                      <- optional, quoted with a leading apostrophe
    ' PIN 24 FLASH TO MASS
    BMW Serie 3 (E46) 2.0 D ...      <- free-form vehicle / application lines

Blank lines separate records.  Outputs JSON + markdown tables for the
protocol database under 01-recon/.
"""
import json
import os
import re
import sys


def parse(path):
    raw = open(path, "rb").read().decode("latin1")
    lines = raw.split("\r\n")
    records = []
    cur = None

    def flush():
        if cur and (cur["name"] or cur["vehicles"] or cur["ids"]):
            cur["name"] = cur["name"] or ""
            records.append(cur)

    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            if cur is not None:
                flush()
            cur = {"name": s[1:].strip(), "ids": [], "notes": [], "vehicles": [], "src": os.path.basename(path)}
            continue
        if cur is None:
            continue
        if s.startswith("id="):
            for part in s[3:].split(","):
                part = part.strip()
                if part.isdigit():
                    cur["ids"].append(int(part))
            continue
        if s.startswith("'"):
            cur["notes"].append(s[1:].strip())
            continue
        # separator-only decorations (dashes, etc.) are layout, keep them out
        if set(s) <= set("-") and len(s) > 3:
            continue
        cur["vehicles"].append(s)
    flush()
    return records


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    all_recs = []
    for f in ("auto.dll", "auto2.dll"):
        if os.path.exists(f):
            recs = parse(f)
            print("%-12s %3d profiles" % (f, len(recs)))
            all_recs.extend(recs)

    # chk files available on disk
    chkdir = "chk"
    chks = set()
    if os.path.isdir(chkdir):
        chks = {os.path.splitext(x)[0].lower() for x in os.listdir(chkdir)}

    for r in all_recs:
        r["chk_present"] = r["name"].lower() in chks

    with open(os.path.join(outdir, "ecu-profiles.json"), "w", encoding="utf-8") as fh:
        json.dump(all_recs, fh, indent=1, ensure_ascii=False)

    with open(os.path.join(outdir, "ecu-profiles.md"), "w", encoding="utf-8") as fh:
        fh.write("# EOBD1260 ECU profile database (auto.dll / auto2.dll)\n\n")
        fh.write("Parsed from the plain-text profile tables shipped with the tool.\n")
        fh.write("`chk` column marks profiles that have a matching `chk/<name>.chk` parameter file.\n\n")
        fh.write("| profile | ids | chk file | notes | applications |\n|---|---|---|---|---|\n")
        for r in all_recs:
            apps = "; ".join(r["vehicles"])
            notes = " | ".join(r["notes"])
            fh.write("| `%s` | %s | %s | %s | %s |\n" % (
                r["name"],
                ",".join(str(i) for i in r["ids"]) or "-",
                "yes" if r["chk_present"] else "no",
                notes.replace("|", "/"),
                apps.replace("|", "/"),
            ))

    print("profiles total:", len(all_recs))
    print("with chk file:", sum(1 for r in all_recs if r["chk_present"]))
    print("unique names:", len({r["name"] for r in all_recs}))


main()
