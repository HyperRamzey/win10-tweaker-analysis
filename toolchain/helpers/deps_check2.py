import dnfile

for path in [r"G:\projects\w10t_work\w10t.exe", r"G:\projects\w10t_work\payload1.dll"]:
    print("=" * 20, path)
    try:
        dn = dnfile.dnPE(path)
    except Exception as e:
        print("  parse fail:", e)
        continue
    ar = dn.net.mdtables.AssemblyRef
    tr = dn.net.mdtables.TypeRef
    mr = dn.net.mdtables.MemberRef
    names = {}
    if ar:
        for i, row in enumerate(ar, start=1):
            n = str(row.Name)
            names[i] = n
            if 'Deps' in n or 'eps' in n:
                v = row
                print(f"  AssemblyRef[{i}]: {n!r} utf8={n.encode('utf-8').hex()}")
                try:
                    print(f"     version={row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}")
                except Exception as e:
                    print("     ver?", e)
    else:
        print("  no AssemblyRef table")
    if tr:
        hits = 0
        for row in tr:
            rs = row.ResolutionScope
            tbl = getattr(rs, 'table', None)
            idx = getattr(rs, 'row_index', None)
            if tbl == 'AssemblyRef' and idx in names and 'eps' in names[idx]:
                print(f"  TypeRef -> [{idx} {names[idx]!r}] {row.TypeNamespace}.{row.TypeName}")
                hits += 1
        print("  typeref hits:", hits)
