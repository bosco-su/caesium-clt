#!/usr/bin/env python3
"""Fail if a PE has dynamic-CRT or Windows 8+ dependencies.

Used by CI to guarantee the Win7 build stays dependency-free.
"""

import os
import struct
import sys

BLACKLIST_PREFIXES = (
    "vcruntime140",
    "msvcp140",
    "concrt140",
    "ucrtbase",
    "api-ms-win-crt",
    "bcryptprimitives",
    "api-ms-win-core-synch-l1-2-0",
)

SUSPICIOUS_FUNCS = (
    "processprng",
    "waitonaddress",
    "wakebyaddress",
    "getsystemtimepreciseasfiletime",
    "setthreaddescription",
    "gettemppath2",
)


def _u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def _u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def parse_pe(path):
    with open(path, "rb") as fh:
        data = fh.read()

    if data[:2] != b"MZ":
        raise ValueError("not a PE file (missing MZ)")
    pe_off = _u32(data, 0x3C)
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("not a PE file (missing PE signature)")

    coff = pe_off + 4
    machine = _u16(data, coff)
    nsec = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    magic = _u16(data, opt)
    if magic not in (0x10B, 0x20B):
        raise ValueError("unknown optional header magic 0x%x" % magic)
    is64 = magic == 0x20B
    dd = opt + (112 if is64 else 96)

    sections = []
    sec_off = opt + opt_size
    for i in range(nsec):
        s = sec_off + 40 * i
        sections.append((
            _u32(data, s + 12),   # VirtualAddress
            _u32(data, s + 8),    # VirtualSize
            _u32(data, s + 20),   # PointerToRawData
            _u32(data, s + 16),   # SizeOfRawData
        ))

    def rva_to_off(rva):
        for vaddr, vsize, rawptr, rawsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawptr + (rva - vaddr)
        return None

    def read_cstr(rva):
        off = rva_to_off(rva)
        if off is None:
            return None
        end = data.index(b"\0", off)
        return data[off:end].decode("latin-1", "replace")

    imports = {}
    imp_rva = _u32(data, dd + 8 * 1)
    if imp_rva:
        off = rva_to_off(imp_rva)
        while off is not None:
            orig_thunk = _u32(data, off)
            name_rva = _u32(data, off + 12)
            first_thunk = _u32(data, off + 16)
            if orig_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break
            dll = read_cstr(name_rva) or "?"
            funcs = []
            thunk_rva = orig_thunk or first_thunk
            t = rva_to_off(thunk_rva)
            if t is not None:
                step = 8 if is64 else 4
                high = 1 << 63 if is64 else 1 << 31
                while True:
                    ent = struct.unpack_from("<Q", data, t)[0] if is64 else _u32(data, t)
                    if ent == 0:
                        break
                    if not (ent & high):
                        fo = rva_to_off(ent)
                        if fo is not None:
                            end = data.index(b"\0", fo + 2)
                            funcs.append(data[fo + 2:end].decode("latin-1", "replace"))
                    t += step
            imports.setdefault(dll, [])
            imports[dll].extend(funcs)
            off += 20

    delay = []
    d_rva = _u32(data, dd + 8 * 13)
    if d_rva:
        off = rva_to_off(d_rva)
        while off is not None:
            name_rva = _u32(data, off + 4)
            int_rva = _u32(data, off + 16)
            if name_rva == 0 and int_rva == 0:
                break
            dll = read_cstr(name_rva)
            if dll:
                delay.append(dll)
            off += 32

    return machine, is64, imports, delay


def main():
    if len(sys.argv) != 2:
        print("usage: verify_pe.py <exe>")
        return 2
    path = sys.argv[1]
    if not os.path.isfile(path):
        print("ERROR: file not found: %s" % path)
        return 2

    machine, is64, imports, delay = parse_pe(path)

    arch = {0x8664: "x86_64", 0x014C: "i386"}.get(machine, "unknown(0x%04x)" % machine)
    print("file    : %s" % path)
    print("machine : %s" % arch)
    print("format  : %s" % ("PE32+ (64-bit)" if is64 else "PE32 (32-bit)"))
    print("imports :")
    for dll in sorted(imports, key=str.lower):
        print("   - %-45s (%d funcs)" % (dll, len(imports[dll])))
    if delay:
        print("delay imports :")
        for dll in delay:
            print("   - %s" % dll)

    failures = []
    for dll in list(imports) + delay:
        low = dll.lower()
        for bad in BLACKLIST_PREFIXES:
            if low.startswith(bad):
                failures.append(dll)
                break

    suspicious = []
    for dll, funcs in imports.items():
        for fn in funcs:
            if any(s in fn.lower() for s in SUSPICIOUS_FUNCS):
                suspicious.append("%s!%s" % (dll, fn))

    if suspicious:
        print("\nWin8+ APIs statically imported:")
        for s in sorted(set(suspicious)):
            print("   - %s" % s)

    if failures:
        print("\nFAIL: forbidden dependency(ies): %s" % ", ".join(sorted(set(failures))))
        return 1
    if suspicious:
        print("\nFAIL: Windows 8+ API imports would break Windows 7")
        return 1

    print("\nOK: no dynamic CRT / Win8+ dependencies detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
