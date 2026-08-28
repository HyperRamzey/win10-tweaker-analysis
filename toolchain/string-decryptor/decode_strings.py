import re, struct, io

SRC = r"G:\projects\w10t_work\koi_fixed_decompiled.cs"
BLOB = r"G:\projects\w10t_work\dumped\string_blob_1.bin"
OUT = r"G:\projects\w10t_work\string_map.tsv"

blob = open(BLOB, 'rb').read()
text = io.open(SRC, 'r', encoding='utf-16').read()

NAME = r'((?:\\u[0-9a-fA-F]{4})+)'
decls = re.findall(r'internal static - ' + NAME + r'<->\(int id\)', text)
assert len(decls) == 5, f"expected 5 decryptors, got {len(decls)}"

# constants per declaration (rid 5..9 order)
CONSTS = [
    (994551305, 0x5501E6A3),
    (834812457, 0xB7B11),
    (-528178527, 0x4A2795E4),
    (-372400731, 0x42F5579),
    (663864581, -1969804901),
]
name2pair = {decls[i]: i for i in range(5)}

def decode(key, mul, xor):
    v = (key * mul) & 0xFFFFFFFF
    v ^= (xor & 0xFFFFFFFF)
    off = (v & 0x3FFFFFFF) << 2
    if off + 4 > len(blob):
        return None, "off-range"
    count = struct.unpack_from('<I', blob, off)[0]
    if count > 2048 or off + 4 + count > len(blob):
        return None, f"bad-count({count})"
    try:
        s = blob[off+4:off+4+count].decode('utf-8')
    except UnicodeDecodeError:
        return None, "utf8"
    if any(ord(c) < 9 for c in s):
        return None, "ctrl"
    return s, None

# gather call sites with their exact decryptor name
calls = re.findall(NAME + r'<string>\((-?\d+)\)', text)
print(f"call sites: {len(calls)}")

results = {}
fails = {}
unknown_name = 0
for name, key_s in calls:
    key = int(key_s)
    if key in results:
        continue
    pi = name2pair.get(name)
    if pi is None:
        unknown_name += 1
        fails.setdefault('unknown-name', []).append(key)
        continue
    s, err = decode(key, *CONSTS[pi])
    if s is None:
        fails.setdefault(err, []).append(key)
    else:
        results[key] = s

print(f"unique decoded: {len(results)}")
for err, keys in sorted(fails.items(), key=lambda kv: -len(kv[1]))[:10]:
    print(f"  FAIL {err}: {len(keys)} sample={keys[:3]}")

with io.open(OUT, 'w', encoding='utf-8', newline='') as f:
    for k in sorted(results):
        s = results[k]
        s = s.replace('\\', '\\\\').replace('\t', '\\t').replace('\r', '\\r').replace('\n', '\\n')
        f.write(f"{k}\t{s}\n")
print(f"written: {OUT}")

for k in [1278538785, 905975941, 967659936, -226742804, -1313128484, 80547734, -2147406520]:
    print(k, '->', repr(results.get(k)))
