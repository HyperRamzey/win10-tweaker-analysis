import dnfile, struct, sys

koi = r"G:\projects\w10t_work\koi.netmodule"
mem = r"G:\projects\w10t_work\dumped\raw_08__Unknown_.bin"

dn = dnfile.dnPE(koi)
frva = dn.net.mdtables.FieldRVA
fld = dn.net.mdtables.Field
print(f"FieldRVA rows: {len(frva) if frva else 0}")
rows = []
if frva:
    for i, row in enumerate(frva, start=1):
        rid = row.field.row_index if hasattr(row.field, 'row_index') else int(row.field)
        name = None
        try:
            frow = fld[rid]
            name = str(frow.name) if frow else None
        except Exception:
            pass
        rows.append((i, row.rva, rid, name))
        print(f"  FieldRVA[{i}]: field_rid={rid} rva=0x{row.rva:x} name={name!r}")

file_bytes = open(koi, 'rb').read()
mem_bytes = open(mem, 'rb').read()
print(f"file size={len(file_bytes)} mem size={len(mem_bytes)}")

# find section mapping in file (RVA->file offset)
import pefile
pe = pefile.PE(koi, fast_load=True)
def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return rva - s.VirtualAddress + s.PointerToRawData
    return None

for i, rva, rid, name in rows:
    off = rva2off(rva)
    # guess size: next rva - this rva, else 64
    sizes = sorted(set(r for _, r, _, _ in rows))
    idx = sizes.index(rva)
    end = sizes[idx+1] if idx+1 < len(sizes) else rva+64
    size = min(end - rva, 4096)
    fb = file_bytes[off:off+size] if off is not None else b''
    mb = mem_bytes[rva:rva+size] if rva < len(mem_bytes) else b''
    same = fb == mb
    print(f"rva=0x{rva:x} fileoff={off} size~{size} file==mem: {same}")
    print(f"  file: {fb[:32].hex(' ')}")
    print(f"  mem : {mb[:32].hex(' ')}")
