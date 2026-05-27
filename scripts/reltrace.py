#!/usr/bin/env python3
"""
Trace the exact memory writes made by the dynamic loader.

Strategy:
  1. Spawn the glibc loader with the target ELF, under gdb.
  2. Single-step into the new process (`starti`) — we land at the loader's
     own entry point. The loader hasn't touched the binary yet.
  3. Locate the binary's load base from /proc/PID/maps.
  4. Set a temporary breakpoint at base + e_entry (the binary's first
     user-code instruction) and continue. The loader runs:
        - mmap'ing PT_LOAD segments
        - reading PT_DYNAMIC and applying DT_REL{A,R} + DT_JMPREL relocs
        - running DT_INIT_ARRAY constructors
     and finally jumps to e_entry, where our breakpoint fires.
  5. Dump every writable PT_LOAD segment from /proc/PID/mem.
  6. Diff against the bytes that segment would contain straight from
     the file (file[p_offset:p_offset+p_filesz], padded with zeros
     out to p_memsz for .bss).
  7. Print every changed 8-byte word as (vaddr, old, new) — that *is*
     the relocation write stream.

For musl ELFs run under the glibc loader this still works for the load
+ relocation phase; the program would crash later in musl's _start, but
we stop *before* any user code executes so we never get there.
"""
from __future__ import annotations
import argparse, os, struct, subprocess, sys, tempfile
from pathlib import Path


# ----- minimal ELF parser -------------------------------------------------

PT_LOAD = 1
PF_W = 0x2


def parse_elf(path: Path):
    with path.open("rb") as f:
        ident = f.read(16)
        assert ident[:4] == b"\x7fELF", "not an ELF"
        assert ident[4] == 2, "only ELF64 supported"
        assert ident[5] == 1, "only little-endian supported"
        f.seek(0x18)
        e_entry, e_phoff = struct.unpack("<QQ", f.read(16))
        f.seek(0x36)
        e_phentsize, e_phnum = struct.unpack("<HH", f.read(4))
        loads = []
        for i in range(e_phnum):
            f.seek(e_phoff + i * e_phentsize)
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align \
                = struct.unpack("<IIQQQQQQ", f.read(56))
            if p_type == PT_LOAD:
                loads.append({
                    "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr,
                    "filesz": p_filesz, "memsz": p_memsz, "align": p_align,
                })
        with path.open("rb") as f2:
            file_bytes = f2.read()
        return {"entry": e_entry, "loads": loads, "file": file_bytes,
                "path": str(path)}


# ----- gdb driver ---------------------------------------------------------

GDB_SCRIPT = r"""
set confirm off
set pagination off
set startup-with-shell off
set print elements 0
set logging file {logfile}
set logging redirect on
set logging enabled on
file {loader}
set args {binary}
set environment LD_LIBRARY_PATH={ld_library_path}
starti
python
import gdb, re, os, json
binary = "{binary}"
entry  = {entry}
inf  = gdb.selected_inferior()
pid  = inf.pid
maps = open(f"/proc/{{pid}}/maps").read()

# Find the first mapping whose pathname matches our binary.
# At this point only the loader is mapped — the binary mappings only appear
# after the loader has mmap'd it. So we first continue until it shows up.
def find_base():
    txt = open(f"/proc/{{pid}}/maps").read()
    base = None
    for line in txt.splitlines():
        if line.endswith(binary):
            lo = int(line.split('-')[0], 16)
            if base is None or lo < base:
                base = lo
    return base

# Run until binary appears. Step through loader by repeatedly continuing
# at known glibc internal symbols. Simplest: catch syscall mmap and check.
gdb.execute("catch syscall mmap")
while find_base() is None:
    gdb.execute("continue")
gdb.execute("delete breakpoints")

base = find_base()
bp_addr = base + entry
gdb.execute(f"tbreak *{{hex(bp_addr)}}")
gdb.execute("continue")

# Confirm we're stopped at e_entry; dump writable segments.
maps = open(f"/proc/{{pid}}/maps").read()
print("=== /proc/PID/maps at e_entry ===")
print(maps)
print(f"=== load base = {{hex(base)}}  e_entry = {{hex(entry)}} ===")

# Dump every writable byte the loader has touched in this image.
# We pass the dump targets via {dump_script}.
exec(open("{dump_script}").read())
gdb.execute("quit")
end
"""


def run(loader_path: str, binary: str, musl_dir: str, elf, dump_dir: str):
    dump_script_path = Path(dump_dir) / "dump.py"
    log_path        = Path(dump_dir) / "gdb.log"
    # Build the python-in-gdb dump script: writes each writable PT_LOAD to disk.
    lines = ["import gdb"]
    for i, seg in enumerate(elf["loads"]):
        if not (seg["flags"] & PF_W):
            continue
        out = Path(dump_dir) / f"seg{i}.bin"
        lines.append(
            f'gdb.execute("dump binary memory {out} '
            f'(char*)({hex(seg["vaddr"])} + $arg_base) '
            f'(char*)({hex(seg["vaddr"])} + $arg_base + {seg["memsz"]}))" '
            ".replace('$arg_base', hex(base)))"
        )
    dump_script_path.write_text("\n".join(lines))

    script = GDB_SCRIPT.format(
        logfile=log_path, loader=loader_path, binary=binary,
        ld_library_path=musl_dir, entry=elf["entry"],
        dump_script=dump_script_path,
    )
    script_path = Path(dump_dir) / "drv.gdb"
    script_path.write_text(script)

    subprocess.run(
        ["gdb", "--batch", "-x", str(script_path)],
        check=False, timeout=60,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # gdb logged to `log_path`; print it.
    if log_path.exists():
        sys.stdout.write(log_path.read_text())


def diff_segments(elf, dump_dir: str):
    print("\n=== relocation-write diff ===")
    total_writes = 0
    for i, seg in enumerate(elf["loads"]):
        if not (seg["flags"] & PF_W):
            continue
        dump_path = Path(dump_dir) / f"seg{i}.bin"
        if not dump_path.exists():
            print(f"  segment {i}: no dump produced")
            continue
        # Reconstruct what the segment SHOULD be (straight from the file,
        # zero-padded out to p_memsz).
        f_off, f_sz, m_sz = seg["offset"], seg["filesz"], seg["memsz"]
        file_bytes = elf["file"][f_off : f_off + f_sz]
        expected = file_bytes + b"\x00" * (m_sz - f_sz)

        actual = dump_path.read_bytes()
        if len(actual) != len(expected):
            print(f"  segment {i}: size mismatch dump={len(actual)} "
                  f"expected={len(expected)}; skipping")
            continue

        # Walk 8 bytes at a time aligned to the vaddr boundary.
        writes = []
        v = seg["vaddr"]
        for off in range(0, len(expected) - 7, 8):
            o, a = expected[off:off+8], actual[off:off+8]
            if o != a:
                writes.append((v + off,
                               struct.unpack("<Q", o)[0],
                               struct.unpack("<Q", a)[0]))
        total_writes += len(writes)
        print(f"  segment {i}: vaddr={hex(seg['vaddr'])} memsz={m_sz}  "
              f"{len(writes)} 8-byte writes")
        for vaddr, old, new in writes[:20]:
            print(f"    [vaddr {hex(vaddr):>10}]  {hex(old):>20} -> {hex(new):>20}")
        if len(writes) > 20:
            print(f"    ... ({len(writes) - 20} more)")
    print(f"\ntotal: {total_writes} 8-byte writes by loader")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--loader", default="/lib64/ld-linux-x86-64.so.2")
    ap.add_argument("--musl-dir",
                    default="corpus/unpacked/v3.23/main/x86_64/musl-1.2.5-r23/lib")
    args = ap.parse_args()

    binary = str(Path(args.binary).resolve())
    elf = parse_elf(Path(binary))
    print(f"binary: {binary}")
    print(f"  e_entry: {hex(elf['entry'])}")
    print(f"  PT_LOAD segments: {len(elf['loads'])}, "
          f"writable: {sum(1 for s in elf['loads'] if s['flags'] & PF_W)}")

    with tempfile.TemporaryDirectory(prefix="reltrace-") as td:
        run(args.loader, binary, str(Path(args.musl_dir).resolve()), elf, td)
        diff_segments(elf, td)


if __name__ == "__main__":
    main()
