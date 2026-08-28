import dnfile
dn = dnfile.dnPE(r"G:\projects\w10t_work\koi.netmodule")
ar = dn.net.mdtables.AssemblyRef
tr = dn.net.mdtables.TypeRef
mr = dn.net.mdtables.MemberRef

names = {}
for i, row in enumerate(ar, start=1):
    n = str(row.Name)
    names[i] = n
    print(f"AssemblyRef[{i}]: {n!r} utf8={n.encode('utf-8').hex()}")

print("---TypeRefs per System.Deps variant---")
for row in tr:
    rs = row.ResolutionScope
    tbl = getattr(rs, 'table', None)
    idx = getattr(rs, 'row_index', None)
    if tbl == 'AssemblyRef' and idx in (6, 14):
        print(f"  [{idx} {names[idx]!r}] {row.TypeNamespace}.{row.TypeName}")

print("---MemberRefs via classes scoped to those refs (indirect)---")
# MemberRef.Class can be TypeRef; count how many ultimately resolve to each
typeref_scope = {}
for i, row in enumerate(tr, start=1):
    rs = row.ResolutionScope
    tbl = getattr(rs, 'table', None)
    idx = getattr(rs, 'row_index', None)
    if tbl == 'AssemblyRef':
        typeref_scope[i] = idx
cnt = {6: 0, 14: 0}
for row in mr:
    cls = row.Class
    tbl = getattr(cls, 'table', None)
    idx = getattr(cls, 'row_index', None)
    if tbl == 'TypeRef' and idx in typeref_scope and typeref_scope[idx] in cnt:
        cnt[typeref_scope[idx]] += 1
print("memberref counts:", cnt)
