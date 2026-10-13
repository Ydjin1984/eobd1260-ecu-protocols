"""FTDI D2XX K-line transport for the EOBD1260 replica loader.

The original EOBD1260.exe talks to the cable exclusively through ftd2xx.dll
(D2XX, not a virtual COM port).  Verified import list and semantics:

    FT_OpenEx, FT_Close, FT_Read, FT_Write, FT_SetBaudRate,
    FT_SetDataCharacteristics, FT_SetTimeouts, FT_Purge,
    FT_SetRts, FT_ClrRts, FT_SetDtr, FT_ClrDtr, FT_ListDevices

There is no FT_SetBitMode import, so K-line / L-line levels are driven with the
RTS and DTR modem-control lines - exactly what this module does.  That is fast
enough for slow init (5 baud = 200 ms per bit) and for the K-line wake pulses,
which is why the original gets away with it.

Only ctypes is used, so the module runs on a bare CPython install.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import sys
import time
from ctypes import byref, c_char_p, c_uint, c_ulong, c_ubyte, c_void_p, POINTER

# --- D2XX constants ---------------------------------------------------------
FT_OK = 0
FT_INVALID_HANDLE = 1
FT_DEVICE_NOT_FOUND = 2
FT_DEVICE_NOT_OPENED = 3
FT_IO_ERROR = 4
FT_INSUFFICIENT_RESOURCES = 5

FT_BITS_8 = 8
FT_STOP_BITS_1 = 0
FT_PARITY_NONE = 0
FT_PARITY_ODD = 1
FT_PARITY_EVEN = 2

FT_FLOW_NONE = 0
FT_PURGE_RX = 1
FT_PURGE_TX = 2

FT_OPEN_BY_SERIAL_NUMBER = 1
FT_OPEN_BY_DESCRIPTION = 2
FT_OPEN_BY_LOCATION = 4

# The original asks for devices with these two list calls (see sub_574CD0):
#   FT_ListDevices(count, NULL, FT_LIST_NUMBER_ONLY)   -> 0x80000000
#   FT_ListDevices(i, buf, FT_LIST_BY_INDEX|FT_OPEN_BY_DESCRIPTION) -> 0x40000001
FT_LIST_NUMBER_ONLY = 0x80000000
FT_LIST_BY_INDEX = 0x40000000
FT_LIST_ALL = 0x20000000
FT_LIST_BY_DESCRIPTION = FT_OPEN_BY_DESCRIPTION

DEFAULT_DLLS = (
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ftd2xx.dll"),
    "ftd2xx.dll",
    "ftd2xx64.dll",
)


class FtdiError(RuntimeError):
    pass


def _load_library(path: str | None = None):
    candidates = [path] if path else []
    candidates += list(DEFAULT_DLLS)
    last = None
    for c in candidates:
        if not c:
            continue
        try:
            return ctypes.WinDLL(c)
        except OSError as exc:  # pragma: no cover - platform dependent
            last = exc
    raise FtdiError("cannot load ftd2xx.dll (%s)" % last)


class FtdiDevice:
    """Thin wrapper over the D2XX API, mirroring the original's usage."""

    def __init__(self, dll_path: str | None = None):
        self.dll = _load_library(dll_path)
        self._bind()
        self.handle = c_void_p()
        self._open = False

    def _bind(self):
        d = self.dll
        self._FT_ListDevices = d.FT_ListDevices
        self._FT_ListDevices.argtypes = [c_void_p, c_char_p, c_ulong]
        self._FT_ListDevices.restype = c_ulong

        self._FT_OpenEx = d.FT_OpenEx
        self._FT_OpenEx.argtypes = [c_void_p, c_ulong, POINTER(c_void_p)]
        self._FT_OpenEx.restype = c_ulong

        self._FT_Close = d.FT_Close
        self._FT_Close.argtypes = [c_void_p]
        self._FT_Close.restype = c_ulong

        self._FT_Write = d.FT_Write
        self._FT_Write.argtypes = [c_void_p, c_void_p, c_ulong, POINTER(c_ulong)]
        self._FT_Write.restype = c_ulong

        self._FT_Read = d.FT_Read
        self._FT_Read.argtypes = [c_void_p, c_void_p, c_ulong, POINTER(c_ulong)]
        self._FT_Read.restype = c_ulong

        self._FT_SetBaudRate = d.FT_SetBaudRate
        self._FT_SetBaudRate.argtypes = [c_void_p, c_ulong]
        self._FT_SetBaudRate.restype = c_ulong

        self._FT_SetDataCharacteristics = d.FT_SetDataCharacteristics
        self._FT_SetDataCharacteristics.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte]
        self._FT_SetDataCharacteristics.restype = c_ulong

        self._FT_SetTimeouts = d.FT_SetTimeouts
        self._FT_SetTimeouts.argtypes = [c_void_p, c_ulong, c_ulong]
        self._FT_SetTimeouts.restype = c_ulong

        self._FT_Purge = d.FT_Purge
        self._FT_Purge.argtypes = [c_void_p, c_ulong]
        self._FT_Purge.restype = c_ulong

        for name in ("FT_SetRts", "FT_ClrRts", "FT_SetDtr", "FT_ClrDtr"):
            fn = getattr(d, name)
            fn.argtypes = [c_void_p]
            fn.restype = c_ulong
            setattr(self, "_" + name, fn)

    # -- device discovery ---------------------------------------------------
    @staticmethod
    def describe(dll_path: str | None = None):
        dll = _load_library(dll_path)
        count = c_ulong(0)
        if dll.FT_ListDevices(byref(count), None, FT_LIST_NUMBER_ONLY) != FT_OK:
            raise FtdiError("FT_ListDevices(number) failed")
        out = []
        for i in range(count.value):
            buf = ctypes.create_string_buffer(64)
            rc = dll.FT_ListDevices(c_void_p(i), buf, FT_LIST_BY_INDEX | FT_LIST_BY_DESCRIPTION)
            if rc == FT_OK:
                out.append(buf.value.decode("latin1"))
        return out

    # -- lifecycle ----------------------------------------------------------
    def open(self, serial: str | None = None, description: str | None = None):
        """Open by serial number (preferred) or by description string."""
        if serial:
            key, flag = serial, FT_OPEN_BY_SERIAL_NUMBER
        elif description:
            key, flag = description, FT_OPEN_BY_DESCRIPTION
        else:
            devs = self.describe()
            if not devs:
                raise FtdiError("no FTDI devices found")
            key, flag = devs[0], FT_OPEN_BY_DESCRIPTION
        rc = self._FT_OpenEx(key.encode("latin1"), flag, byref(self.handle))
        if rc != FT_OK:
            raise FtdiError("FT_OpenEx(%r) failed: %d" % (key, rc))
        self._open = True
        self.purge()
        return self

    def close(self):
        if self._open:
            self._FT_Close(self.handle)
            self._open = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- configuration ------------------------------------------------------
    def set_baudrate(self, baud: int):
        return self._check(self._FT_SetBaudRate(self.handle, baud), "FT_SetBaudRate")

    def set_line(self, data_bits=FT_BITS_8, stop_bits=FT_STOP_BITS_1, parity=FT_PARITY_NONE):
        return self._check(self._FT_SetDataCharacteristics(self.handle, data_bits, stop_bits, parity),
                           "FT_SetDataCharacteristics")

    def set_timeouts(self, read_ms: int, write_ms: int):
        return self._check(self._FT_SetTimeouts(self.handle, read_ms, write_ms), "FT_SetTimeouts")

    def purge(self, rx=True, tx=True):
        mask = (FT_PURGE_RX if rx else 0) | (FT_PURGE_TX if tx else 0)
        return self._check(self._FT_Purge(self.handle, mask), "FT_Purge")

    # -- modem control lines (drive K / L levels) ---------------------------
    def set_rts(self):
        return self._check(self._FT_SetRts(self.handle), "FT_SetRts")

    def clr_rts(self):
        return self._check(self._FT_ClrRts(self.handle), "FT_ClrRts")

    def set_dtr(self):
        return self._check(self._FT_SetDtr(self.handle), "FT_SetDtr")

    def clr_dtr(self):
        return self._check(self._FT_ClrDtr(self.handle), "FT_ClrDtr")

    # -- data ---------------------------------------------------------------
    def write(self, data: bytes) -> int:
        n = c_ulong(0)
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        rc = self._FT_Write(self.handle, buf, len(data), byref(n))
        self._check(rc, "FT_Write")
        return n.value

    def read(self, size: int, timeout_ms: int | None = None) -> bytes:
        """Read up to `size` bytes.  D2XX returns what it has, so callers loop."""
        if timeout_ms is not None:
            self.set_timeouts(timeout_ms, timeout_ms)
        buf = ctypes.create_string_buffer(size)
        n = c_ulong(0)
        rc = self._FT_Read(self.handle, buf, size, byref(n))
        self._check(rc, "FT_Read")
        return buf.raw[: n.value]

    def read_exact(self, size: int, timeout_ms: int, poll_ms: int = 1) -> bytes:
        deadline = time.monotonic() + timeout_ms / 1000.0
        out = bytearray()
        while len(out) < size and time.monotonic() < deadline:
            chunk = self.read(size - len(out), poll_ms)
            if chunk:
                out += chunk
        return bytes(out)

    # -- slow init helpers --------------------------------------------------
    def send_5baud(self, address: int, bit_time: float = 0.2, rts_active_high: bool = False):
        """ISO 14230 5-baud slow init: start bit, 8 data bits LSB-first, stop bit.

        On the FTDI K-line cables the K level follows RTS; `rts_active_high`
        flips the polarity for boards wired the other way round.
        """
        def level(bit: int):
            if rts_active_high:
                (self.set_rts if bit else self.clr_rts)()
            else:
                (self.clr_rts if bit else self.set_rts)()

        level(0)                      # start bit
        time.sleep(bit_time)
        for i in range(8):
            level((address >> i) & 1)
            time.sleep(bit_time)
        level(1)                      # stop bit
        time.sleep(bit_time)

    def k_line_pulse(self, level_high: bool, seconds: float):
        """Hold the K line at a level for `seconds` (fast-init wake pulses)."""
        (self.set_rts if level_high else self.clr_rts)()
        time.sleep(seconds)

    def _check(self, rc: int, what: str):
        if rc != FT_OK:
            raise FtdiError("%s failed: %d" % (what, rc))
        return rc


# --- checksums --------------------------------------------------------------
def xor_checksum(data: bytes) -> int:
    """XOR of all bytes - used by the original's sub_4018C0 (Delphi XOR checksum)."""
    c = 0
    for b in data:
        c ^= b
    return c


def sum_checksum(data: bytes) -> int:
    """ISO 14230 / KWP2000 additive checksum."""
    return sum(data) & 0xFF


if __name__ == "__main__":
    devs = FtdiDevice.describe()
    print("FTDI devices:", devs or "(none)")
