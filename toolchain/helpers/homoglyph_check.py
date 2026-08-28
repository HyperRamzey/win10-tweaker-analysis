import io

out = io.open(r"G:\projects\w10t_work\homoglyph_report.txt", "w", encoding="utf-8")

def s(x):
    # dnfile heap string items: use str() / .value
    try:
        return str(x)
    except Exception:
        try:
            return x.value
        except Exception:
            return repr(x)

import dnfile
dn = dnfile.dnPE(r"G:\projects\w10t_work\koi.netmodule")

out.write("--- koi.netmodule AssemblyRef names ---\n")
tb = dn.net.mdtables.AssemblyRef
if tb:
    for row in tb:
        name = s(row.Name)
        cps = " ".join("U+%04X" % ord(c) for c in name)
        out.write("ASMREF %r -> %s\n" % (name, cps))

out.write("\n--- TypeRef namespaces containing 'D' + 'ps' ---\n")
tr = dn.net.mdtables.TypeRef
nsset = {}
names = {}
if tr:
    for row in tr:
        ns = s(row.TypeNamespace)
        tn = s(row.TypeName)
        if "Deps" in ns or "D" + chr(0x435) + "ps" in ns:
            nsset[ns] = nsset.get(ns, 0) + 1
            names.setdefault(ns, []).append(tn)
for ns, c in nsset.items():
    cps = " ".join("U+%04X" % ord(ch) for ch in ns)
    out.write("TYPEREF-NS %r x%d -> %s\n" % (ns, c, cps))
    out.write("   types: %s\n" % ", ".join(sorted(set(names[ns]))[:20]))

out.close()
print("written")
