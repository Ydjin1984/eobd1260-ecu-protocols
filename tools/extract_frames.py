"""Extract protocol byte frames from the dumped protocol-method assembly.

How a protocol method works (observed in sub_43ED70 and the whole family):

    mov  [esp+74h+var_20], 23h        ; frame bytes built on the stack,
    mov  [esp+74h+var_1F], 0Fh        ; one byte per instruction
    ...
    push [esi+250864h]                ; arg: timeout hi
    push [esi+250860h]                ; arg: timeout lo
    push eax                          ; arg: length
    lea  eax, [esp+80h+var_64]        ; arg: frame pointer
    push eax
    mov  ecx, esi                     ; Self
    call dword ptr [edx+4Ch]          ; transport send (VMT+0x4C)

So every send site is preceded by a `lea ..., [.. + var_XX]` naming the frame
base, and the frame bytes are `mov` immediates at `var_XX+n`.  Bytes that come
from registers (bl/dl/cl/al) are runtime data — addresses, seed/key, counters —
and are reported as unknown.

Output: frames.json  { "<func>": { "frames": [ {base, len, bytes, send_index} ] } }
"""
import json
import os
import re
import sys

ASM_DIR = r"C:\eobd-re\dump\funcs"
OUT = r"C:\eobd-re\dump\frames.json"

VAR_RE = re.compile(r'var_([0-9A-Fa-f]+)(?:\+(\d+))?')
# mov  [esp+74h+var_20], 23h        /  mov byte ptr [...], 0Fh  /  mov [...], 'x'
MOV_RE = re.compile(
    r'^\s*s*([0-9A-F]{8})\s+mov\s+(?:byte ptr\s+)?\[([^\]]+)\],\s*(.+?)\s*(?:;.*)?$'
)
LEA_RE = re.compile(r'^\s*([0-9A-F]{8})\s+lea\s+\w+,\s*\[([^\]]+)\]\s*(?:;.*)?$')
SEND_RE = re.compile(r'^\s*([0-9A-F]{8})\s+call\s+dword ptr \[(\w+)\+4Ch\]\s*(?:;.*)?$')
PUSH_IMM = re.compile(r'^\s*([0-9A-F]{8})\s+push\s+([0-9A-F]+h|\d+)\s*(?:;.*)?$')


def imm_value(txt):
    """parse an immediate operand to an int, or None if it is a register."""
    t = txt.strip()
    if t.endswith('h'):
        try:
            return int(t[:-1], 16)
        except ValueError:
            return None
    m = re.match(r"^'(.?)'$", t)
    if m:
        return ord(m.group(1))
    if re.fullmatch(r'\d+', t):
        return int(t)
    return None


def frame_offset(expr):
    """map a stack expression to a byte position inside the frame buffer.

    IDA prints locals as `esp+74h+var_64`; var_64 is -0x64 from ebp.  We keep
    the position as -(value) so that increasing addresses grow the frame.
    """
    m = VAR_RE.search(expr)
    if not m:
        return None
    base = int(m.group(1), 16)
    plus = int(m.group(2)) if m.group(2) else 0
    return -(base) + plus


def parse_function(path):
    lines = open(path, encoding='utf-8', errors='replace').read().split('\n')

    writes = {}       # frame position -> byte value
    send_bases = []   # (line_index, base position, addr)
    pending_lea = None

    for i, ln in enumerate(lines):
        m = LEA_RE.match(ln)
        if m:
            pending_lea = (i, frame_offset(m.group(2)), m.group(1))
            continue
        m = SEND_RE.match(ln)
        if m:
            if pending_lea and i - pending_lea[0] <= 12:
                send_bases.append((i, pending_lea[1], m.group(1)))
            pending_lea = None
            continue
        m = MOV_RE.match(ln)
        if m:
            off = frame_offset(m.group(2))
            val = imm_value(m.group(3))
            if off is not None and val is not None and 0 <= val < 256:
                writes[off] = val

    if not sends_present(send_bases):
        pass

    # assign each written byte to the frame whose base is the greatest base <= it
    # K-line frames are small; anything beyond MAX_FRAME is a page buffer, so we
    # bound the window and take the tight extent of the bytes actually written.
    MAX_FRAME = 264
    frames = []
    for idx, (line_i, base, addr) in enumerate(send_bases):
        lo = base
        nxt = send_bases[idx + 1][1] if idx + 1 < len(send_bases) else None
        limit = lo + MAX_FRAME
        if nxt is not None and lo < nxt < limit:
            limit = nxt
        inside = [p for p in writes if lo <= p < limit]
        hi = (max(inside) + 1) if inside else min(lo + 8, limit)
        if hi <= lo:
            hi = lo + 8
        buf = [writes.get(off) for off in range(lo, hi)]
        frames.append({
            "send_index": idx,
            "send_addr": addr,
            "base": lo,
            "len": hi - lo,
            "bytes": buf,
            "known": sum(1 for b in buf if b is not None),
        })
    return {"frames": frames}


def sends_present(sb):
    return bool(sb)


def main():
    out = {}
    files = sorted(f for f in os.listdir(ASM_DIR) if f.endswith('.asm') and f.startswith('sub_'))
    for fn in files:
        try:
            out[fn[:-4]] = parse_function(os.path.join(ASM_DIR, fn))
        except Exception as exc:
            out[fn[:-4]] = {"error": str(exc)}
    json.dump(out, open(OUT, 'w', encoding='utf-8'), indent=1)
    tot = sum(len(v.get('frames', [])) for v in out.values())
    withframes = sum(1 for v in out.values() if v.get('frames'))
    print("[frames] %d functions scanned, %d have frames, %d frames total" %
          (len(files), withframes, tot))


main()
