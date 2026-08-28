import re, io, struct

text = io.open(r"G:\projects\w10t_work\koi_fixed_decompiled.cs", encoding='utf-16').read()
NAME = r'((?:\\u[0-9a-fA-F]{4})+)'
decls = re.findall(r'internal static - ' + NAME + r'<->\(int id\)', text)
print('decls:', len(decls))

CONSTS = [
    (994551305, 0x5501E6A3),
    (834812457, 0xB7B11),
    (-528178527, 0x4A2795E4),
    (-372400731, 0x42F5579),
    (663864581, -1969804901),
]
blob = open(r"G:\projects\w10t_work\dumped\string_blob_1.bin", 'rb').read()

def trace(key, mul, xor):
    v = (key * mul) & 0xFFFFFFFF
    v ^= (xor & 0xFFFFFFFF)
    tag = v >> 30
    off = (v & 0x3FFFFFFF) << 2
    info = f"v=0x{v:08x} tag={tag} off={off}"
    if off + 4 <= len(blob):
        count = struct.unpack_from('<I', blob, off)[0]
        info += f" count={count}"
        if count < 2048 and off + 4 + count <= len(blob):
            try:
                info += f" str={blob[off+4:off+4+count].decode('utf-8')!r}"
            except Exception as e:
                info += f" utf8err={e}"
    return info

for i, d in enumerate(decls):
    sites = re.findall(re.escape(d) + r'<string>\((-?\d+)\)', text)
    uniq = sorted(set(int(s) for s in sites))
    print(f'decl[{i}] call_sites={len(sites)} unique={len(uniq)} sample={uniq[:3]}')
    for k in uniq[:2]:
        print(f'   key={k} with own pair{i}: {trace(k, *CONSTS[i])}')
        for j in range(5):
            if j == i: continue
            t = trace(k, *CONSTS[j])
            if 'tag=0' in t:
                print(f'   key={k} with pair{j}: {t}')
