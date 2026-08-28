import dnfile
dn = dnfile.dnPE(r"G:\projects\w10t_work\koi.netmodule")
tr = dn.net.mdtables.TypeRef
ar = dn.net.mdtables.AssemblyRef
names = {}
for i, row in enumerate(ar, start=1):
    names[i] = str(row.Name)

print("--- TypeRefs whose NAMESPACE contains 'Deps' (any scope) ---")
for i, row in enumerate(tr, start=1):
    ns = str(row.TypeNamespace or '')
    nm = str(row.TypeName or '')
    if 'eps' in ns or 'eps' in nm:
        rs = row.ResolutionScope
        tbl = getattr(rs, 'table', None)
        idx = getattr(rs, 'row_index', None)
        scope = f"{tbl}[{idx}]={names.get(idx,'?')}" if tbl=='AssemblyRef' else f"{tbl}[{idx}]"
        print(f"  TypeRef[{i}] {ns}.{nm}  scope={scope!r}")

print("--- all distinct TypeRef namespaces (top) ---")
from collections import Counter
c = Counter(str(r.TypeNamespace or '') for r in tr)
for ns, n in c.most_common(40):
    print(f"  {n:4d}  {ns}")
