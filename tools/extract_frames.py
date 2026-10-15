"""Extract protocol byte frames from the dumped protocol-method assembly (v2).

Rewritten 2026-10-15 after AUDIT-2.  The v1 extractor had five defects:

  1. stores through byte registers (`mov dl, 0B8h` ... `mov [buf], dl`) were
     invisible -> false `--` holes;
  2. stores at raw esp offsets without a var_ name were dropped;
  3. a single global "position -> last value" map merged mutually exclusive
     branches (last-write-wins);
  4. frame length was the extent of writes, not the length actually sent
     (`push imm` right before the transport call);
  5. send sites were only linked to a preceding `lea` within 12 lines, so
     sites with a longer build sequence were lost.

v2 runs a per-path data-flow over the disassembly: it builds the basic-block
graph, executes it symbolically (registers + frame memory), evaluates decided
conditional jumps and forks at undecidable ones, tracks byte registers, raw
esp offsets (esp anchored via the var_XX names IDA prints), `rep stos` clears
and the byte-copy idioms.  Every transport send (`call dword ptr [reg+4Ch]`)
materialises one byte list; the buffer pointer and the length come from the
pushed arguments.

Conservative rules:
  * a position a function reads back that was only ever set by a memset-like
    clear is treated as a receive buffer: loads yield unknown and the bytes
    become null (the response is written by the transport, invisible here);
  * loop iterations that write different values to the same frame position
    mark it null and record the observed set in "variants";
  * stores with an unresolved index register mark a bounded span as null.

Frame record:
  send_index, send_addr  first send site (call instruction)
  base, len              frame window (position P = address - ebp)
  bytes                  int | null per byte
  known                  number of non-null bytes
  len_src                "push"   - from the pushed length argument
                         "extent" - pointer/len not provable, write extent used
  sends, occurrences     all call sites / all recorded paths
  path                   branch decisions of the first occurrence
  variants               {position: [values]} for loop-variant positions
"""
import json
import os
import re
import sys

ASM_DIR = r"C:\eobd-re\dump\funcs"
OUT = r"C:\eobd-re\dump\frames.json"

MAX_STEPS = 300_000        # instruction steps per state
MAX_EVENTS = 2000          # recorded send snapshots per function
MAX_FORKS = 6000           # undecided-branch forks per function
MAX_REENTRY = 12           # block re-entries per path (unknown-bound loops)
MAX_FRAME_EXTENT = 512     # cap for the "extent" length fallback
IDX_SPAN_DEFAULT = 0x100   # span for stores with an unresolved index register

LINE_RE = re.compile(r'^([0-9A-F]{8})\s+([a-z][a-z0-9]*)\s*(.*)$')
COMMENT_CHAR_RE = re.compile(r"^\s*'(?:\\[a-z]|[^'])'\s*$")
MEM_RE = re.compile(r'^(?:(byte|word|dword)\s+ptr\s+)?\[(.+)\]$')
VAR_RE = re.compile(r'var_([0-9A-Fa-f]+)')
ARG_RE = re.compile(r'arg_([0-9A-Fa-f]+)')
HEX_RE = re.compile(r'^([+\-]?)([0-9A-Fa-f]+)h$')
DEC_RE = re.compile(r'^([+\-]?)(\d+)$')
C_DECL_RE = re.compile(r'^(.+?);\s*//\s*\[esp\+[0-9A-Fa-f]+h\]\s*\[ebp-([0-9A-Fa-f]+)h\]')

REG32 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
REG16 = {"ax": "eax", "bx": "ebx", "cx": "ecx", "dx": "edx", "si": "esi",
         "di": "edi", "bp": "ebp"}
REG8 = {"al": ("eax", 0), "ah": ("eax", 1), "bl": ("ebx", 0), "bh": ("ebx", 1),
        "cl": ("ecx", 0), "ch": ("ecx", 1), "dl": ("edx", 0), "dh": ("edx", 1)}
ALLREGS = set(REG32) | set(REG16) | set(REG8)

JCC = {"jz", "je", "jnz", "jne", "jl", "jle", "jg", "jge", "jb", "jbe",
       "ja", "jae", "js", "jns", "jo", "jno", "jp", "jnp", "jecxz"}
SIGNED = {"jl", "jle", "jg", "jge"}
UNSIGNED = {"jb", "jbe", "ja", "jae"}
FLAG_CLOBBERS = {"and", "or", "xor", "add", "sub", "adc", "sbb", "inc", "dec",
                 "neg", "shl", "shr", "sar", "imul", "mul", "not"}

UNKNOWN = None  # sentinel is simply Python None in values


# --------------------------------------------------------------- parsing ----

def parse_lines(path):
    """-> list of (addr, mnemonic, [operands], char_comment_flag)."""
    out = []
    for ln in open(path, encoding='utf-8', errors='replace'):
        char = False
        if ';' in ln:
            ln, comment = ln.split(';', 1)
            if COMMENT_CHAR_RE.match(comment):
                char = True
        ln = ln.rstrip()
        if not ln:
            continue
        m = LINE_RE.match(ln)
        if not m:
            continue
        mnem = m.group(2)
        if mnem in ("align", "db", "dd", "dw", "nop", "int3"):
            continue
        ops = [x.strip() for x in m.group(3).split(",")] if m.group(3).strip() else []
        out.append((int(m.group(1), 16), mnem, ops, char))
    return out


def parse_ctypes(path):
    """ebp-relative position -> size in bytes, from Hex-Rays declarations."""
    types = {}
    try:
        src = open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        return types
    for ln in src.split('\n'):
        m = C_DECL_RE.match(ln)
        if not m:
            continue
        decl = re.sub(r'\[.*\]', '', m.group(1))
        if '*' in decl:
            size = 4
        elif '__int64' in decl or 'double' in decl or 'long long' in decl:
            size = 8
        elif '__int16' in decl or '_WORD' in decl or 'short' in decl or 'wchar' in decl:
            size = 2
        elif 'char' in decl or '_BYTE' in decl or '__int8' in decl or 'bool' in decl:
            size = 1
        elif ('__int32' in decl or 'int' in decl or '_DWORD' in decl
              or 'float' in decl or 'long' in decl or 'unsigned' in decl):
            size = 4
        else:
            continue
        types[-int(m.group(2), 16)] = size
    return types


_IMM_CACHE = {}
_IMM_MISS = object()


def imm_of(tok):
    hit = _IMM_CACHE.get(tok, _IMM_MISS)
    if hit is not _IMM_MISS:
        return hit
    m = HEX_RE.match(tok)
    if m:
        v = int(m.group(1) + m.group(2), 16)
    else:
        m = DEC_RE.match(tok)
        v = int(m.group(1) + m.group(2)) if m else None
    _IMM_CACHE[tok] = v
    return v


_TERMS_CACHE = {}


_IMAGE = None
_OFF_RE = re.compile(r'(?:byte|word|dword|flt|dbl|unk)_([0-9A-F]{6,8})$')


def load_image():
    """Map VA -> bytes for the original EOBD1260.exe image."""
    global _IMAGE
    if _IMAGE is not None:
        return _IMAGE
    import struct
    _IMAGE = {}
    for path in (r"C:\eobd-re\orig\EOBD1260.exe",):
        try:
            d = open(path, 'rb').read()
        except OSError:
            continue
        if d[:2] != b'MZ':
            continue
        e = struct.unpack_from('<I', d, 0x3C)[0]
        nsec = struct.unpack_from('<H', d, e + 6)[0]
        optsize = struct.unpack_from('<H', d, e + 20)[0]
        sh = e + 24 + optsize
        secs = []
        for i in range(nsec):
            b = sh + i * 40
            vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', d, b + 8)
            secs.append((vaddr, vsize, raddr, rsize))
        _IMAGE = {'data': d, 'secs': secs}
        break
    return _IMAGE


def read_va(va, n):
    img = load_image()
    if not img:
        return None
    d, secs = img['data'], img['secs']
    for vaddr, vsize, raddr, rsize in secs:
        if vaddr <= va and va + n <= vaddr + max(vsize, rsize):
            off = raddr + (va - vaddr)
            if 0 <= off and off + n <= len(d):
                return d[off:off + n]
    return None


_MEM_CACHE = {}


def mem_split(op):
    """MEM_RE.match + group extraction, cached by operand text."""
    hit = _MEM_CACHE.get(op)
    if hit is None:
        m = MEM_RE.match(op.strip())
        hit = (m.group(1), m.group(2)) if m else (None, None)
        _MEM_CACHE[op] = hit
    return hit


def split_terms(expr):
    hit = _TERMS_CACHE.get(expr)
    if hit is None:
        hit = [(m.group(1) or '+', m.group(2).strip())
               for m in re.finditer(r'([+\-]?)([^+\-]+)', expr)]
        _TERMS_CACHE[expr] = hit
    return hit


# ------------------------------------------------------------ registers -----

def reg_get(regs, name):
    if name in REG32:
        return regs.get(name)
    if name in REG16:
        base = REG16[name]
        v = regs.get(base)
        if isinstance(v, int):
            return v & 0xFFFF
        if isinstance(v, tuple) and v[0] == 'b' and 0 in v[1] and 1 in v[1]:
            return v[1][0] | (v[1][1] << 8)
        return None
    if name in REG8:
        base, shift = REG8[name]
        v = regs.get(base)
        if isinstance(v, int):
            return (v >> (shift * 8)) & 0xFF
        if isinstance(v, tuple) and v[0] == 'b':
            return v[1].get(shift)
        return None
    return None


def reg_set(regs, name, val):
    if name in REG32:
        regs[name] = val
        return
    if name in REG16:
        base = REG16[name]
        old = regs.get(base)
        if isinstance(val, int):
            v = val & 0xFFFF
            if isinstance(old, int):
                regs[base] = (old & ~0xFFFF) | v
            else:
                m = dict(old[1]) if isinstance(old, tuple) and old[0] == 'b' else {}
                m[0] = v & 0xFF
                m[1] = (v >> 8) & 0xFF
                regs[base] = ('b', m)
        else:
            if isinstance(old, tuple) and old[0] == 'b':
                m = dict(old[1])
                m.pop(0, None)
                m.pop(1, None)
                regs[base] = ('b', m) if m else None
            else:
                regs[base] = None
        return
    if name in REG8:
        base, shift = REG8[name]
        old = regs.get(base)
        if isinstance(val, int):
            v = val & 0xFF
            if isinstance(old, int):
                mask = 0xFF << (shift * 8)
                regs[base] = (old & ~mask) | (v << (shift * 8))
            elif isinstance(old, tuple) and old[0] == 'b':
                m = dict(old[1])
                m[shift] = v
                regs[base] = ('b', m)
            else:
                regs[base] = ('b', {shift: v})
        else:
            if isinstance(old, tuple) and old[0] == 'b':
                m = dict(old[1])
                m.pop(shift, None)
                regs[base] = ('b', m) if m else None
            else:
                regs[base] = None


def shift_val(val, delta, regs):
    """Pointer arithmetic on frame pointers / ints."""
    if isinstance(val, int):
        return val + delta
    if isinstance(val, tuple) and val[0] == 'fp':
        return ('fp', val[1] + delta)
    return None


# ------------------------------------------------------------------ state ---

class St(object):
    __slots__ = ("regs", "frame", "cleared", "pushed", "flags", "pk", "sid",
                 "steps", "fork_unknown", "visited", "_C")

    def __init__(self, sid=0):
        self.regs = {r: None for r in REG32}
        self.frame = {}
        self.cleared = set()
        self.pushed = []
        self.flags = None
        self.pk = ()
        self.sid = sid
        self.steps = 0
        self.fork_unknown = False
        self.visited = set()
        self._C = None

    def clone(self, sid):
        st = St(sid)
        st.regs = dict(self.regs)
        st.frame = dict(self.frame)
        st.cleared = set(self.cleared)
        st.pushed = list(self.pushed)
        st.flags = self.flags
        st.pk = self.pk
        st.steps = self.steps
        st.visited = set(self.visited)
        st._C = self._C
        return st


class Analyzer(object):
    def __init__(self, stem, instrs, types):
        self.stem = stem
        self.instrs = instrs
        self.types = types
        self.events = []
        self.loopvar_vals = {}  # position -> set of values seen across loop iterations
        self.loopvar_blocks = {}  # position -> blocks where the variation was seen
        self.entries = {}       # state id -> {block_start: (frame copy, regs copy)}
        self.entry_counts = {}  # pk -> {block_start: n}  (cap for unknown loops)
        self.reads = set()
        self.regions = []
        self.unresolved = 0
        self.truncated = False
        self.loops_capped = False
        self.forks = 0
        self.steps = 0
        self.bstart = {}
        self.sid_seq = 0

    def next_sid(self):
        self.sid_seq += 1
        return self.sid_seq

    # ----------------------------------------------------------- helpers ---

    def resolve_mem(self, op, st):
        """Parse a [size ptr] [expr] operand.

        -> (kind, pos, explicit_size, encoded_disp, base_is_esp)
        """
        ex, expr = mem_split(op)
        if expr is None:
            return None
        kind, pos, newC, disp, base_esp = self.resolve_addr(expr, st)
        if newC is not None:
            st._C = newC
        return (kind, pos, ex, disp, base_esp)

    def imm_store_len_size(self, i, disp, base_esp, value):
        """Infer an immediate store width from the instruction length.

        IDA omits `byte ptr` for byte stores into typed int locals, so the
        encoded size is recovered from (next address - address): `mov r/m8,
        imm8` is 3 bytes shorter than `mov r/m32, imm32` on the same
        addressing form.
        """
        if i + 1 >= len(self.instrs):
            return None
        length = self.instrs[i + 1][0] - self.instrs[i][0]
        if length <= 0 or length > 20:
            return None
        if disp == 0 and not base_esp:
            return None  # mod=00 with base ebp means a disp32 follows; skip
        if disp == 0:
            d = 0
        elif -128 <= disp <= 127:
            d = 1
        else:
            d = 4
        base = 1 + 1 + (1 if base_esp else 0) + d
        cands = []
        if length == base + 1:
            cands.append(1)
        if length == base + 3:
            cands.append(2)
        if length == base + 4:
            cands.append(4)
        if len(cands) != 1:
            return None
        size = cands[0]
        if value is not None:
            v = value & 0xFFFFFFFF
            if size == 1 and not (v <= 0xFF or v >= 0xFFFFFF00):
                return None
            if size == 2 and not (v <= 0xFFFF or v >= 0xFFFF0000):
                return None
        return size

    def resolve_addr(self, expr, st):
        """-> (kind, pos, new_anchor).  kind: 'frame' | 'fpx' | 'unk'."""
        const = 0
        var_off = 0
        reg_sum = 0
        saw_esp = False
        saw_ebp = False
        had_var = False
        idx_unknown = False
        base_fp = None
        prev_var = False
        for sign, tok in split_terms(expr):
            s = 1 if sign == '+' else -1
            if tok == 'esp':
                saw_esp = True
                prev_var = False
                continue
            if tok == 'ebp':
                saw_ebp = True
                prev_var = False
                continue
            if tok in ALLREGS:
                v = reg_get(st.regs, tok)
                if isinstance(v, tuple) and v[0] == 'fp':
                    if base_fp is None:
                        base_fp = v[1]
                    else:
                        idx_unknown = True
                elif isinstance(v, int):
                    reg_sum += s * v
                else:
                    idx_unknown = True
                prev_var = False
                continue
            m = VAR_RE.match(tok)
            if m:
                var_off += s * (-int(m.group(1), 16))
                had_var = True
                prev_var = True
                continue
            m = ARG_RE.match(tok)
            if m:
                var_off += s * (8 + int(m.group(1), 16))
                had_var = True
                prev_var = True
                continue
            v = imm_of(tok)
            if v is not None:
                if prev_var:
                    var_off += s * v
                else:
                    const += s * v
                continue
            return ('unk', None, None, None, None)
        if saw_esp:
            newC = const if had_var else None
            cused = newC if newC is not None else st._C
            if cused is None:
                return ('unk', None, None, None, None)
            pos = const + var_off + reg_sum - cused
            return ('fpx' if idx_unknown else 'frame', pos, newC,
                    const + var_off, True)
        if saw_ebp:
            return ('fpx' if idx_unknown else 'frame',
                    const + var_off + reg_sum, None, const + var_off, False)
        if base_fp is not None and not idx_unknown:
            return ('frame', base_fp + const + var_off + reg_sum, None,
                    const + var_off, False)
        return ('unk', None, None, None, None)

    def load_frame(self, st, pos, size):
        """Little-endian load; cleared positions are receive-buffer bytes."""
        if size is None:
            size = 4
        total = 0
        for i in range(size):
            p = pos + i
            if p in st.cleared:
                return None
            v = st.frame.get(p)
            if not isinstance(v, int):
                return None
            total |= v << (8 * i)
        return total

    MAX_FRAME_POS = 2048

    def store(self, st, pos, val, size, clear=False):
        frame = st.frame
        for i in range(size):
            p = pos + i
            if not -0x20000 <= p <= 0x20000:
                continue  # huge far-away local: not worth byte tracking
            if len(frame) >= self.MAX_FRAME_POS and p not in frame:
                continue  # tracked frame is saturated: drop new far writes
            st.frame[p] = (val >> (8 * i)) & 0xFF if isinstance(val, int) else None
            if clear:
                st.cleared.add(p)
            else:
                st.cleared.discard(p)

    def store_byte(self, st, pos, val, clear=False):
        if not -0x20000 <= pos <= 0x20000:
            return
        if len(st.frame) >= Analyzer.MAX_FRAME_POS and pos not in st.frame:
            return
        st.frame[pos] = val if isinstance(val, int) else None
        if clear:
            st.cleared.add(pos)
        else:
            st.cleared.discard(pos)

    def size_of(self, pos, explicit, imm_char=False):
        if explicit:
            return {'byte': 1, 'word': 2, 'dword': 4}[explicit]
        if imm_char:
            return 1
        return self.types.get(pos)

    def idx_span(self, i, reg):
        if not reg:
            return IDX_SPAN_DEFAULT
        for j in range(i - 1, max(-1, i - 90), -1):
            a, m, ops, ch = self.instrs[j]
            if m == 'cmp' and len(ops) == 2:
                for side, other in ((ops[0], ops[1]), (ops[1], ops[0])):
                    if side == reg:
                        v = imm_of(other)
                        if v is not None and 2 <= v <= 0x800:
                            return v
        return IDX_SPAN_DEFAULT

    def reg_index_of(self, op):
        m = MEM_RE.match(op.strip())
        if not m:
            return ''
        for sign, tok in split_terms(m.group(2)):
            if tok in ALLREGS and tok not in ('esp', 'ebp'):
                return tok
        return ''

    def val_op(self, op, st):
        """Operand value: int / ('fp', pos) / None."""
        op = op.strip()
        if op.startswith('offset ') or op.startswith('large '):
            return None
        if op in ALLREGS:
            return reg_get(st.regs, op)
        v = imm_of(op)
        if v is not None:
            return v
        mem = self.resolve_mem(op, st)
        if mem:
            kind, pos, ex = mem[0], mem[1], mem[2]
            if kind == 'frame':
                self.reads.add(pos)
                sz = self.size_of(pos, ex)
                if ex is None and 'var_' not in op and 'arg_' not in op:
                    sz = sz or 1
                return self.load_frame(st, pos, sz)
            if kind == 'fpx':
                self.reads.add(pos)
            return None
        return None

    # ------------------------------------------------------------- sends ---

    def do_send(self, st, addr):
        items = st.pushed
        bi = None
        for i in range(len(items) - 1, max(-1, len(items) - 7), -1):
            if items[i][0] == 'fp':
                bi = i
                break
        if bi is None:
            # send of a static image buffer: push imm(len) + push offset NAME
            if (len(items) >= 2 and items[-1][0] == 'off'
                    and items[-2][0] == 'int'):
                m = _OFF_RE.match(items[-1][1])
                ln = items[-2][1]
                if m and 0 < ln <= 0x10000:
                    va = int(m.group(1), 16)
                    buf = read_va(va, ln)
                    if buf is not None:
                        del items[max(0, len(items) - 4):]
                        self.snapshot_image(addr, va, ln, buf)
                        return
            self.unresolved += 1
            del items[max(0, len(items) - 4):]
            return
        bufpos = items[bi][1]
        ln = items[bi - 1][1] if bi - 1 >= 0 and items[bi - 1][0] == 'int' else None
        del items[max(0, bi - 3):bi + 1]
        self.snapshot(st, addr, bufpos, ln)

    def snapshot_image(self, addr, va, ln, buf):
        """Frame sent from a static buffer of the binary image.

        Contents are the *initial* image bytes: the original may patch such a
        buffer at runtime (checksums, ids), so len_src is "image" - the length
        is still the pushed one, the content is not runtime-verified.
        """
        if len(self.events) >= MAX_EVENTS:
            self.truncated = True
            return
        self.events.append(((), addr, va, ln, 'image', tuple(buf),
                            frozenset(), 0, frozenset()))

    def snapshot(self, st, addr, base, ln):
        if len(self.events) >= MAX_EVENTS:
            self.truncated = True
            return
        len_src = 'push'
        if ln is None:
            inside = [p for p in st.frame if base <= p < base + MAX_FRAME_EXTENT]
            ln = (max(inside) - base + 1) if inside else 0
            len_src = 'extent'
        if ln <= 0:
            return
        if ln > 0x4000:
            ln = 0x4000
            len_src += '+capped'
        out = []
        applied = []
        for k in range(ln):
            pos = base + k
            lb = self.loopvar_blocks.get(pos)
            if pos in self.loopvar_vals and lb and (lb & st.visited):
                out.append(None)
                applied.append(pos)
            else:
                out.append(st.frame.get(pos))
        self.events.append((st.pk, addr, base, ln, len_src, tuple(out),
                            frozenset(st.cleared), st.steps,
                            frozenset(applied)))

    # ------------------------------------------------------------ blocks ---

    def build_blocks(self):
        instrs = self.instrs
        starts = {instrs[0][0]}
        for i, (a, m, ops, ch) in enumerate(instrs):
            if m in JCC or m == 'jmp':
                if ops:
                    t = self.target_of(ops[0])
                    if t is not None:
                        starts.add(t)
                if i + 1 < len(instrs):
                    starts.add(instrs[i + 1][0])
            elif m in ('retn', 'ret'):
                if i + 1 < len(instrs):
                    starts.add(instrs[i + 1][0])
        blocks = []
        cur = None
        for i, (a, m, ops, ch) in enumerate(instrs):
            if cur is None:
                cur = [a, i, i]
            cur[2] = i
            if m in JCC or m in ('jmp', 'retn', 'ret'):
                blocks.append((cur[0], cur[1], cur[2]))
                cur = None
            elif i + 1 < len(instrs) and instrs[i + 1][0] in starts:
                blocks.append((cur[0], cur[1], cur[2]))
                cur = None
        if cur:
            blocks.append((cur[0], cur[1], cur[2]))
        self.bstart = {b[0]: b for b in blocks}

    def target_of(self, op):
        m = re.search(r'loc_([0-9A-F]{4,8})$', op.strip())
        if m:
            return int(m.group(1), 16)
        # plain numeric target (rare)
        m = re.search(r'\b([0-9A-F]{8})\b', op.strip())
        if m:
            return int(m.group(1), 16)
        return None

    def jump_index(self, target):
        lo, hi = 0, len(self.instrs) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            a = self.instrs[mid][0]
            if a == target:
                return mid
            if a < target:
                lo = mid + 1
            else:
                hi = mid - 1
        return len(self.instrs)

    def enter_block(self, st, baddr):
        # counts keyed by the accumulated branch-decision set: loop-back clones
        # share it, so an unbounded forking loop is capped
        counts = self.entry_counts.setdefault(st.pk, {})
        n = counts.get(baddr, 0) + 1
        counts[baddr] = n
        ent = self.entries.setdefault(st.sid, {})
        if len(st.frame) <= 1500:
            prev = ent.get(baddr)
            if prev is not None:
                pframe, pregs = prev
                if pframe == st.frame and pregs == st.regs:
                    return False  # fixed point: frame and registers both still
                for pos, v in st.frame.items():
                    pv = pframe.get(pos)
                    if isinstance(v, int) and isinstance(pv, int) and v != pv:
                        self.loopvar_vals.setdefault(pos, set()).update((v, pv))
                        self.loopvar_blocks.setdefault(pos, set()).add(baddr)
            ent[baddr] = (dict(st.frame), dict(st.regs))
        else:
            ent.pop(baddr, None)  # big frame: entry diffs not worth the cost
        if st.fork_unknown and n > MAX_REENTRY:
            self.loops_capped = True
            return False
        st.visited.add(baddr)
        st.fork_unknown = False
        return True

    # --------------------------------------------------------------- run ---

    def run(self):
        self.build_blocks()
        instrs = self.instrs
        if not instrs:
            return
        import time as _time
        t0 = _time.monotonic()
        stack = []
        st = St(self.next_sid())
        stack.append((0, st, True))
        while stack:
            i, st, mark = stack.pop()
            while i < len(instrs):
                addr, mnem, ops, ch = instrs[i]
                if mark:
                    b = self.bstart.get(addr)
                    if b is not None and b[1] == i:
                        if not self.enter_block(st, addr):
                            break
                    mark = False
                st.steps += 1
                self.steps += 1
                if st.steps > MAX_STEPS or self.steps > 2 * MAX_STEPS:
                    self.truncated = True
                    break
                if (self.steps & 0x3FFF) == 0 and _time.monotonic() - t0 > 120:
                    self.truncated = True
                    break
                res = self.exec_one(st, instrs, i)
                if res is None:
                    break
                if res == 'next':
                    i += 1
                    mark = True
                    continue
                # branch: [(idx, state, unknown_arg), ...]
                for entry in res[:-1]:
                    stack.append((entry[0], entry[1], True))
                i, st, mark = res[-1][0], res[-1][1], True
            # path finished

    # ---------------------------------------------------- instruction ---

    def cond_result(self, mnem, st):
        f = st.flags
        if f is None:
            return None
        cf, zf, sf, of = f
        if mnem in ("jz", "je"):
            return zf == 1
        if mnem in ("jnz", "jne"):
            return zf == 0
        if mnem in SIGNED:
            lt = (sf != of)
            return {"jl": lt, "jle": lt or zf == 1,
                    "jg": (not lt) and zf == 0,
                    "jge": (not lt) or zf == 1}[mnem]
        if mnem in UNSIGNED:
            return {"jb": cf == 1, "jbe": cf == 1 or zf == 1,
                    "ja": cf == 0 and zf == 0, "jae": cf == 0}[mnem]
        if mnem == "js":
            return sf == 1
        if mnem == "jns":
            return sf == 0
        return None

    def exec_one(self, st, instrs, i):
        addr, mnem, ops, imm_char = instrs[i]
        regs = st.regs

        if mnem == 'mov' and len(ops) == 2:
            dst, src = ops
            mem = self.resolve_mem(dst, st)
            if mem:
                kind, pos, ex, disp, base_esp = mem
                if kind == 'frame':
                    val = self.val_op(src, st)
                    size = self.size_of(pos, ex, imm_char)
                    if ex is None and not imm_char:
                        # the instruction's operand width decides the store,
                        # not the C type of the whole local
                        if src in REG32:
                            size = 4
                        elif src in REG16:
                            size = 2
                        elif src in REG8:
                            size = 1
                        elif isinstance(val, int):
                            inferred = self.imm_store_len_size(
                                i, (disp if disp is not None else 0),
                                base_esp, val)
                            size = inferred or size or (
                                4 if (val > 0xFFFF or val < -0x8000) else (
                                    2 if (val > 0xFF or val < -0x80) else 1))
                        elif size is None:
                            size = 4
                    self.store(st, pos, val, size)
                    if val is None:
                        for k in range(size):
                            st.cleared.discard(pos + k)
                elif kind == 'fpx':
                    span = self.idx_span(i, self.reg_index_of(dst))
                    for k in range(span):
                        self.store_byte(st, pos + k, None)
                return 'next'
            if dst in ALLREGS:
                val = self.val_op(src, st)
                if isinstance(val, tuple) and val[0] != 'fp':
                    val = None
                reg_set(regs, dst, val)
                return 'next'
            self.val_op(src, st)
            return 'next'

        if mnem in ('movsx', 'movzx') and len(ops) == 2:
            dst, src = ops
            val = None
            if src in ALLREGS:
                val = reg_get(regs, src)
            else:
                mem = self.resolve_mem(src, st)
                if mem:
                    kind, pos, ex = mem[0], mem[1], mem[2]
                    if kind == 'frame':
                        self.reads.add(pos)
                        val = self.load_frame(st, pos, self.size_of(pos, ex))
            if isinstance(val, int):
                if src in REG16:
                    val &= 0xFFFF
                    if mnem == 'movsx' and val & 0x8000:
                        val -= 0x10000
                elif src in REG8:
                    val &= 0xFF
                    if mnem == 'movsx' and val & 0x80:
                        val -= 0x100
            if dst in ALLREGS and dst in REG32:
                reg_set(regs, dst, val)
            return 'next'

        if mnem == 'lea' and len(ops) == 2:
            dst, src = ops
            m = MEM_RE.match(src.strip())
            if m and dst in ALLREGS:
                kind, pos, newC = self.resolve_addr(m.group(2), st)[:3]
                if newC is not None:
                    st._C = newC
                reg_set(regs, dst, ('fp', pos) if kind == 'frame' else None)
            return 'next'

        if mnem == 'push':
            op = ops[0]
            if op in ALLREGS and op not in ('esp', 'ebp'):
                v = reg_get(regs, op)
                if isinstance(v, tuple) and v[0] == 'fp':
                    st.pushed.append(('fp', v[1]))
                elif isinstance(v, int):
                    st.pushed.append(('int', v))
                else:
                    st.pushed.append(('unk', None))
            elif op.startswith('offset '):
                st.pushed.append(('off', op[7:].strip()))
            else:
                v = None if (op in ALLREGS or op.startswith('large ')
                             or MEM_RE.match(op)) else imm_of(op)
                st.pushed.append(('int', v) if isinstance(v, int) else ('unk', None))
            if len(st.pushed) > 40:
                del st.pushed[:-20]
            return 'next'

        if mnem == 'pop':
            if ops and ops[0] in ALLREGS:
                reg_set(regs, ops[0], None)
            if st.pushed:
                st.pushed.pop()
            return 'next'

        if mnem == 'call':
            op = ops[0] if ops else ''
            if '+4Ch]' in op:
                self.do_send(st, addr)
            else:
                nxt = instrs[i + 1] if i + 1 < len(instrs) else None
                if st.pushed and not (nxt and nxt[1] == 'add' and nxt[2]
                                      and nxt[2][0] == 'esp'):
                    st.pushed = []
            regs['eax'] = regs['ecx'] = regs['edx'] = None
            st.flags = None
            return 'next'

        if mnem in ('retn', 'ret'):
            return None

        if mnem in JCC:
            t = self.target_of(ops[0]) if ops else None
            if t is None:
                return None
            res = self.cond_result(mnem, st)
            if res is True:
                return [(self.jump_index(t), st, False)]
            if res is False:
                return 'next'
            self.forks += 1
            if self.forks > MAX_FORKS:
                self.loops_capped = True
                return 'next'
            a2 = st.clone(self.next_sid())
            a1 = st
            base = set(st.pk[-64:])
            a1.pk = tuple(sorted(base | {(addr, False)}))
            a2.pk = tuple(sorted(base | {(addr, True)}))
            a1.fork_unknown = True
            a2.fork_unknown = True
            return [(self.jump_index(t), a2, True), (i + 1, a1, True)]

        if mnem == 'jmp':
            t = self.target_of(ops[0]) if ops else None
            if t is None:
                return None
            return [(self.jump_index(t), st, False)]

        if mnem in ('cmp', 'test') and len(ops) == 2:
            a = self.val_op(ops[0], st)
            b = self.val_op(ops[1], st)
            if not isinstance(a, int) or not isinstance(b, int):
                st.flags = None
            else:
                zf = 1 if a == b else 0
                r = a - b
                sf = 1 if r < 0 else 0
                of = 1 if ((a >= 0) != (b >= 0)) and ((r >= 0) != (a >= 0)) else 0
                cf = 1 if (a & 0xFFFFFFFF) < (b & 0xFFFFFFFF) else 0
                st.flags = (cf, zf, sf, of)
            return 'next'

        if mnem in ('and', 'or', 'xor') and len(ops) == 2 and ops[0] in ALLREGS:
            dst, src = ops
            if dst == 'esp':
                st._C = None
                return 'next'
            a = reg_get(regs, dst)
            if mnem == 'xor' and dst == src:
                reg_set(regs, dst, 0)
            else:
                b = self.val_op(src, st)
                if isinstance(a, int) and isinstance(b, int):
                    reg_set(regs, dst, {'and': a & b, 'or': a | b,
                                        'xor': a ^ b}[mnem])
                else:
                    reg_set(regs, dst, None)
            st.flags = None
            return 'next'

        if mnem in ('add', 'sub') and len(ops) == 2 and ops[0] in ALLREGS:
            dst, src = ops
            v = self.val_op(src, st)
            if dst == 'esp':
                if isinstance(v, int) and st._C is not None and mnem == 'sub':
                    st._C += v
                elif isinstance(v, int) and st._C is not None and mnem == 'add':
                    st._C -= v
                    n = v // 4
                    if 0 < n <= len(st.pushed):
                        del st.pushed[len(st.pushed) - n:]
                else:
                    st._C = None
                return 'next'
            a = reg_get(regs, dst)
            delta = v if mnem == 'add' else (-v if isinstance(v, int) else None)
            if isinstance(delta, int) and (isinstance(a, int) or
                                           (isinstance(a, tuple) and a[0] == 'fp')):
                reg_set(regs, dst, shift_val(a, delta, regs))
            else:
                reg_set(regs, dst, None)
            st.flags = None
            return 'next'

        if mnem == 'and' and len(ops) == 2 and ops[0] == 'esp':
            st._C = None
            return 'next'

        if mnem in ('inc', 'dec') and ops:
            dst = ops[0]
            d = 1 if mnem == 'inc' else -1
            if dst in ALLREGS:
                a = reg_get(regs, dst)
                if isinstance(a, int):
                    reg_set(regs, dst, a + d)
                elif isinstance(a, tuple) and a[0] == 'fp':
                    reg_set(regs, dst, ('fp', a[1] + d))
                else:
                    reg_set(regs, dst, None)
                return 'next'
            mem = self.resolve_mem(dst, st)
            if mem:
                kind, pos, ex = mem[0], mem[1], mem[2]
                if kind == 'frame':
                    self.reads.add(pos)
                    size = self.size_of(pos, ex) or 1
                    v = self.load_frame(st, pos, size)
                    self.store(st, pos, (v + d) if isinstance(v, int) else None,
                               size)
                elif kind == 'fpx':
                    self.reads.add(pos)
            st.flags = None
            return 'next'

        if mnem in ('shl', 'shr', 'sar') and len(ops) == 2 and ops[0] in ALLREGS:
            dst = ops[0]
            a = reg_get(regs, dst)
            b = self.val_op(ops[1], st)
            if isinstance(a, int) and isinstance(b, int) and 0 <= b < 32:
                if mnem == 'shl':
                    reg_set(regs, dst, (a << b) & 0xFFFFFFFF)
                elif mnem == 'shr':
                    reg_set(regs, dst, (a & 0xFFFFFFFF) >> b)
                else:
                    reg_set(regs, dst, a >> b)
            else:
                reg_set(regs, dst, None)
            st.flags = None
            return 'next'

        if mnem == 'neg' and ops and ops[0] in ALLREGS:
            a = reg_get(regs, ops[0])
            reg_set(regs, ops[0], -a if isinstance(a, int) else None)
            st.flags = None
            return 'next'

        if mnem in ('stosd', 'stosb'):
            return self.string_op(st, i, 4 if mnem == 'stosd' else 1)

        if mnem == 'movsd':
            return self.string_op(st, i, 4, copy=True)

        if mnem == 'rep' and ops:
            sub = ops[0]
            if sub in ('stosd', 'stosb'):
                return self.string_op(st, i, 4 if sub == 'stosd' else 1, rep=True)
            if sub == 'movsd':
                return self.string_op(st, i, 4, copy=True, rep=True)
            return 'next'

        if mnem in FLAG_CLOBBERS and len(ops) == 2:
            mem = self.resolve_mem(ops[0], st)
            if mem:
                kind, pos, ex = mem[0], mem[1], mem[2]
                if kind == 'frame':
                    self.reads.add(pos)
                    size = self.size_of(pos, ex) or 1
                    self.store(st, pos, None, size)
                elif kind == 'fpx':
                    self.reads.add(pos)
            st.flags = None
            return 'next'

        return 'next'

    def string_op(self, st, i, width, copy=False, rep=False):
        regs = st.regs
        count = reg_get(regs, 'ecx') if rep else 1
        if rep and not isinstance(count, int):
            count = None
        dst = reg_get(regs, 'edi')
        if isinstance(dst, tuple) and dst[0] == 'fp':
            base = dst[1]
            if count is None:
                for k in range(IDX_SPAN_DEFAULT):
                    self.store_byte(st, base + k * width, None)
                self.reads.add(base)
            else:
                n = count
                if n > 0x8000:
                    n = 0x8000
                val = None if copy else reg_get(regs, 'eax')
                if not copy and isinstance(val, int) and n * width > 0x1000:
                    # huge clear: record the region, skip per-byte state
                    self.regions.append((base, n * width))
                else:
                    for k in range(n):
                        self.store(st, base + k * width, val, width,
                                   clear=(not copy and isinstance(val, int)))
                    if not copy and isinstance(val, int):
                        self.regions.append((base, n * width))
                if n:
                    reg_set(regs, 'edi', ('fp', base + n * width))
        if rep and isinstance(count, int):
            reg_set(regs, 'ecx', 0)
        return 'next'


# ------------------------------------------------------------ extraction ----

def apply_events(an):
    """Apply loop-variant marks and receive-region marks; group frames."""
    flagged = set()
    for (start, length) in an.regions:
        if any(start <= p < start + length for p in an.reads):
            flagged.update(range(start, start + length))
    merged = {}
    order = []
    for (pk, addr, base, ln, len_src, data, cleared, step, applied) in an.events:
        vals = {}
        bytes_ = []
        for k in range(ln):
            pos = base + k
            v = data[k]
            if pos in flagged and pos in cleared:
                v = None
            if pos in applied:
                vals[pos] = sorted(an.loopvar_vals[pos])
            bytes_.append(v)
        key = (base, ln, tuple(bytes_))
        rec = merged.get(key)
        if rec is None:
            rec = {"base": base, "len": ln, "bytes": bytes_,
                   "len_src": len_src, "sends": [], "occ": 0, "variants": {},
                   "vals": {}, "pk": pk}
            merged[key] = rec
            order.append(key)
        rec["sends"].append(addr)
        rec["occ"] += 1
        for p, vv in vals.items():
            rec["vals"].setdefault(p, set()).update(vv)
        if rec["len_src"] != len_src:
            rec["len_src"] = "push+extent"
    used = set()
    final = []
    for k1 in order:
        if k1 in used:
            continue
        acc = merged[k1]
        b1 = list(acc["bytes"])
        # repeat until no more frames can be folded in: a frame that merged
        # later may unlock a pairing that failed on an earlier pass
        changed = True
        while changed:
            changed = False
            for k2 in order:
                if k2 is k1 or k2 in used:
                    continue
                if k2[0] != k1[0] or k2[1] != k1[1]:
                    continue
                b2 = k2[2]
                diff = [i for i in range(k1[1]) if b1[i] != b2[i]]
                if not diff:
                    used.add(k2)
                    acc["sends"].extend(merged[k2]["sends"])
                    acc["occ"] += merged[k2]["occ"]
                    for p_, vv in merged[k2]["vals"].items():
                        acc["vals"].setdefault(p_, set()).update(vv)
                    changed = True
                    continue
                if all(b1[i] is None or b2[i] is None for i in diff):
                    for i in diff:
                        pos = k1[0] + i
                        if b1[i] is None:
                            if b2[i] is not None:
                                acc["vals"].setdefault(pos, set()).add(b2[i])
                        else:
                            acc["vals"].setdefault(pos, set()).add(b1[i])
                            b1[i] = None
                    used.add(k2)
                    acc["sends"].extend(merged[k2]["sends"])
                    acc["occ"] += merged[k2]["occ"]
                    for p_, vv in merged[k2]["vals"].items():
                        acc["vals"].setdefault(p_, set()).update(vv)
                    changed = True
        used.add(k1)
        acc["bytes"] = b1
        acc["variants"] = {p: sorted(v) for p, v in acc["vals"].items()}
        final.append(acc)
    final.sort(key=lambda r: min(r["sends"]) if r["sends"] else 0)
    frames = []
    for idx, r in enumerate(final):
        sends = sorted(set(r["sends"]))
        frames.append({
            "send_index": idx,
            "send_addr": "%08X" % sends[0] if sends else "",
            "base": r["base"],
            "len": r["len"],
            "bytes": r["bytes"],
            "known": sum(1 for b in r["bytes"] if b is not None),
            "len_src": r["len_src"],
            "sends": ["%08X" % s for s in sends],
            "occurrences": r["occ"],
            "path": pk_str(r["pk"]),
            "variants": {p: v for p, v in sorted(r["variants"].items())},
        })
    return frames


def pk_str(pk):
    if not pk:
        return ""
    parts = ["%X:%s" % (a, 'T' if t else 'F') for a, t in pk[-8:]]
    return ",".join(parts)


def analyze(path, cpath):
    instrs = parse_lines(path)
    if not instrs:
        return None, []
    types = parse_ctypes(cpath)
    an = Analyzer(os.path.basename(path)[:-4], instrs, types)
    an.run()
    return an, apply_events(an)


def worker(fn):
    import time as _t
    t0 = _t.time()
    stem = fn[:-4]
    try:
        an, frames = analyze(os.path.join(ASM_DIR, fn),
                             os.path.join(ASM_DIR, stem + '.c'))
    except Exception as exc:
        return stem, {"error": "%s: %s" % (type(exc).__name__, exc)}, 0, False, False, 0, 0
    if an is None:
        return stem, {"frames": []}, 0, False, False, 0, _t.time() - t0
    rec = {"frames": frames}
    if an.truncated:
        rec["truncated"] = True
    if an.loops_capped:
        rec["loops_capped"] = True
    if an.unresolved:
        rec["unresolved_sends"] = an.unresolved
    return (stem, rec, len(frames), an.truncated, an.loops_capped,
            an.unresolved, _t.time() - t0)


def main():
    args = sys.argv[1:]
    out = {}
    total_frames = 0
    funcs_with = 0
    unresolved = 0
    trunc = 0
    files = sorted(f for f in os.listdir(ASM_DIR)
                   if f.endswith('.asm') and f.startswith('sub_'))
    if args:
        files = [f for f in files if any(a in f for a in args)]

    if not args and len(files) > 40:
        # independent per-function analysis -> parallelise
        import multiprocessing as mp
        import time as _t
        nproc = max(1, min(8, (os.cpu_count() or 4)))
        t_all = _t.time()
        with mp.Pool(nproc) as pool:
            for k, (stem, rec, nf, tr, cap, un, dt) in enumerate(
                    pool.imap_unordered(worker, files, chunksize=4), 1):
                out[stem] = rec
                total_frames += nf
                if nf:
                    funcs_with += 1
                trunc += 1 if tr else 0
                unresolved += un
                if dt > 10:
                    print("[slow] %6.1fs %s" % (dt, stem), flush=True)
                if k % 100 == 0:
                    print("[progress] %d/%d elapsed=%.0fs frames=%d"
                          % (k, len(files), _t.time() - t_all, total_frames),
                          flush=True)
        print("[frames] %d functions scanned, %d have frames, %d frames total"
              % (len(files), funcs_with, total_frames), flush=True)
        print("[frames] unresolved send sites: %d; truncated functions: %d"
              % (unresolved, trunc))
        json.dump(out, open(OUT, 'w', encoding='utf-8'), indent=1)
        return
    import time
    slow = []
    t_all = time.time()
    for fi, fn in enumerate(files):
        stem = fn[:-4]
        t0 = time.time()
        try:
            an, frames = analyze(os.path.join(ASM_DIR, fn),
                                 os.path.join(ASM_DIR, stem + '.c'))
        except Exception as exc:
            out[stem] = {"error": "%s: %s" % (type(exc).__name__, exc)}
            print("[error] %s: %s" % (stem, exc))
            continue
        if an is None:
            out[stem] = {"frames": []}
            continue
        rec = {"frames": frames}
        if an.truncated:
            rec["truncated"] = True
        if an.loops_capped:
            rec["loops_capped"] = True
        if an.truncated:
            trunc += 1
        if an.unresolved:
            rec["unresolved_sends"] = an.unresolved
        out[stem] = rec
        total_frames += len(frames)
        if frames:
            funcs_with += 1
        unresolved += an.unresolved
        dt = time.time() - t0
        slow.append((dt, an.steps, stem))
        if (fi + 1) % 100 == 0:
            print("[progress] %d/%d  elapsed=%.0fs  frames=%d"
                  % (fi + 1, len(files), time.time() - t_all, total_frames),
                  flush=True)
        if args:
            print("== %s  frames=%d unresolved=%d truncated=%s" % (
                stem, len(frames), an.unresolved, an.truncated))
            for fr in frames:
                bs = ' '.join('%02X' % b if b is not None else '--'
                              for b in fr["bytes"])
                print("  base=%-6d len=%-4d %-8s sends=%-24s %s%s" % (
                    fr["base"], fr["len"], fr["len_src"],
                    ",".join(fr["sends"])[:24], bs,
                    "  variants=%s" % fr["variants"] if fr["variants"] else ""))
    slow.sort(reverse=True)
    print("[slow] top-12 by seconds:")
    for dt, steps, stem in slow[:12]:
        print("   %6.2fs  steps=%-9d %s" % (dt, steps, stem), flush=True)
    if not args:
        json.dump(out, open(OUT, 'w', encoding='utf-8'), indent=1)
        print("[frames] %d functions scanned, %d have frames, %d frames total"
              % (len(files), funcs_with, total_frames))
        print("[frames] unresolved send sites: %d; truncated functions: %d"
              % (unresolved, trunc))
    else:
        json.dump(out, open(r"C:\eobd-re\dump\frames_test.json", 'w',
                            encoding='utf-8'), indent=1)


if __name__ == '__main__':
    main()
