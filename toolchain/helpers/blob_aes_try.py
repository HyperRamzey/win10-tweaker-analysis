import glob, os, hashlib
from Crypto.Cipher import AES

blobs = sorted(glob.glob(r"G:\projects\w10t_work\dumped\res_nfH9PMep*.bin"))

# candidate seed strings
seeds = [
    "qurjORzRqFFaxuAUHQhvsxwsuqKN",
    "System.Deps", "System.D\u0435ps", "Win 10 Tweaker", "w10t",
    "0e4c2d2ea0ee1b44",
    "50b6f9665170c34c8c251f1c63488cdd",  # stub MVID
    "bc3f6590d2b2fc4dabe4b5e965d92ff3",  # payload MVID
    "66f9b65070514cc38c251f1c63488cdd",  # koi MVID (no dashes)
    "nfH9PMepLjwh8NXsII5tAiddN7pfJ+LQ6rASUExgWT90jAUG93Ei1fkMPvl0DOAQbZqM3dUd/9UMTZuxasWQk+Q1DqSSsw2wVZnVXoRc",
    "nfH9PMepLjyQ7zCDDKAGPcrvoZXaO4fSkD7QwrBkYIk71BRnhpkrrqkDTELPLHSg0PGivP9lsZFffF+fD36nUJHsHeIEfkHpMJm5Hwpc3A==",
]

def keys_from(seed):
    kb = seed.encode("utf-8")
    out = []
    out.append(("md5", hashlib.md5(kb).digest()))
    out.append(("sha1-16", hashlib.sha1(kb).digest()[:16]))
    out.append(("sha256-16", hashlib.sha256(kb).digest()[:16]))
    out.append(("sha256-32", hashlib.sha256(kb).digest()))
    return out

def looks_plain(b):
    if not b: return False
    return b[:2] == b"MZ" or b[:4] == b"BSJB" or b[:4] == b"PK\x03\x04" or b[:4] == b"\x37\x7a\xbc\xaf"

hits = 0
for f in blobs:
    d = open(f, "rb").read()
    name = os.path.basename(f)[:30]
    for seed in seeds:
        for kname, key in keys_from(seed):
            # AES-CBC iv=first16
            if len(d) > 32 and len(key) in (16, 32):
                try:
                    c = AES.new(key, AES.MODE_CBC, d[:16])
                    pt = c.decrypt(d[16:16+ ((len(d)-16)//16)*16])
                    if looks_plain(pt):
                        print("HIT cbc iv16", name, kname, seed[:20], pt[:8]); hits += 1
                except Exception: pass
                try:
                    c = AES.new(key, AES.MODE_CBC, b"\x00"*16)
                    pt = c.decrypt(d[:(len(d)//16)*16])
                    if looks_plain(pt):
                        print("HIT cbc iv0", name, kname, seed[:20], pt[:8]); hits += 1
                except Exception: pass
                try:
                    c = AES.new(key, AES.MODE_ECB)
                    pt = c.decrypt(d[:(len(d)//16)*16])
                    if looks_plain(pt):
                        print("HIT ecb", name, kname, seed[:20], pt[:8]); hits += 1
                except Exception: pass
print("total hits:", hits)
print("(no hits => key is not derivable from these obvious seeds)")
