import re, io

SRC = r"G:\projects\w10t_work\koi_fixed_decompiled.cs"
MAP = r"G:\projects\w10t_work\string_map.tsv"
OUT = r"G:\projects\w10t_work\koi_readable.cs"

strings = {}
for line in io.open(MAP, encoding='utf-8'):
    k, _, s = line.rstrip('\n').partition('\t')
    strings[int(k)] = s

text = io.open(SRC, 'r', encoding='utf-16').read()
print(f"src chars: {len(text)}")

# ConfuserEx invisible identifier codepoints only (never touches visible \u escapes in literals)
INV = r'\\u(?:200[b-f]|202[a-e]|206[0-9a-f]|feff|00ad|034f|061c|180e|17b[45])'
RUN = '(?:' + INV + ')+'

# 1) rename all zero-width identifier runs to stable readable ids
ids = {}
counter = [0]
def ren(m):
    run = m.group(0)
    if run not in ids:
        counter[0] += 1
        ids[run] = f"zw{counter[0]:04d}"
    return ids[run]

text = re.sub(RUN, ren, text, flags=re.IGNORECASE)
print(f"unique zero-width identifiers renamed: {len(ids)}")

# 2) substitute decryptor calls (now with renamed identifiers)
def cs_literal(s):
    s = s.replace('\\', '\\\\').replace('"', '\\"').replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')
    out = []
    for ch in s:
        if ord(ch) < 32:
            out.append(f'\\u{ord(ch):04x}')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'

n_sub = 0
def repl(m):
    global n_sub
    key = int(m.group(1))
    if key in strings:
        n_sub += 1
        return cs_literal(strings[key])
    return m.group(0)

text = re.sub(r'zw\d{4}<string>\((-?\d+)\)', repl, text)
print(f"substituted string calls: {n_sub}")

with io.open(OUT, 'w', encoding='utf-8', newline='') as f:
    f.write(text)
print(f"written: {OUT} ({len(text)} chars)")
