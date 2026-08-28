import glob, os, math, collections

def chi2(data):
    n = len(data)
    cnt = collections.Counter(data)
    exp = n / 256.0
    return sum((c - exp) ** 2 / exp for c in cnt.values())

for f in sorted(glob.glob(r"G:\projects\w10t_work\dumped\res_nfH9PMep*.bin")):
    d = open(f, "rb").read()
    c2 = chi2(d)
    # chi2 ~255 for uniform random; >~300 means non-random structure
    ent = 0.0
    cnt = collections.Counter(d)
    for c in cnt.values():
        p = c / len(d)
        ent -= p * math.log2(p)
    print("%s len=%d chi2=%.1f entropy=%.4f bits/byte unique=%d" %
          (os.path.basename(f)[:40], len(d), c2, ent, len(cnt)))
    # repeating-key XOR detection: look at index-of-coincidence for candidate keylens
    for kl in (4, 8, 16, 32):
        # average chi2 of each key-position slice
        tot = 0
        for off in range(kl):
            slice_ = d[off::kl]
            if len(slice_) > 256:
                tot += chi2(slice_)
        print("   keylen %2d avg-slice-chi2=%.0f" % (kl, tot / kl))
    print()
print("Reference: pure random chi2 ~ 255; XOR-with-short-key shows HIGH slice chi2 at the right keylen")
