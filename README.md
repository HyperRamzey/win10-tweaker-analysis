# Win 10 Tweaker v20.5 — Unpacking & Malware Analysis

Static + dynamic reverse-engineering of **Win 10 Tweaker v20.5** (vendor "XpucT"), a heavily
protected Windows-10 "tweaker" utility. The sample is double-packed (**.NET Reactor / NecroBit**
outside, **ConfuserEx 1.7.0-alpha** inside) and ships as a single executable that decrypts a hidden
.NET module (`koi`) at runtime.

> **Verdict:** a legitimate commercial tweaking utility — **not malware**. No miner, stealer,
> keylogger, RAT, or arbitrary remote-code execution was found. It does carry real but limited
> security concerns (server-directed download of unsigned helper binaries, a trust-all-TLS
> callback, and license phone-home). Full reasoning in [`report/FINAL_REPORT.md`](report/FINAL_REPORT.md).

Microsoft classifies it as `HackTool:Win32/Win10Tweaker!MSR` (hacktool / PUP class), which matches
our findings.

---

## Sample identification (not redistributed)

The binary itself is **not included** in this repository (it is a PUP/hacktool; see
[What is not published](#what-is-not-published-and-why)). Identify it by hash:

| Field | Value |
|---|---|
| SHA256 | `17938E0C5438006FD9BFCE2291F11545619F00D4EF459D6C851E419C321D61F4` |
| MD5 | `917809BCE1896390C0BBA246FF481C48` |
| Product / Version | Win 10 Tweaker / 20.5 |
| Company | XpucT |
| Type | PE32 .NET assembly, AnyCPU, .NET Reactor packed |

---

## Headline findings

- **Unpacked & deobfuscated the full payload.** Recovered the hidden `koi` module (7,674 methods),
  rebuilt it into a decompilable assembly, and decoded **9,315 / 9,320** ConfuserEx-encrypted strings
  into a readable C# source (`koi_readable.cs`, ~4.9 MB) used for all subsystem analysis.
- **No malicious behavior.** Exhaustive sweeps found no miner/stealer/keylogger indicators, no
  credential access, no C2. The only download→execute path fetches genuine Microsoft installers
  (DirectX, .NET 4.7.2) from `download.microsoft.com`, user-initiated.
- **`System.Deps` mystery solved — and it's two DLLs, one hiding behind a homoglyph.** The runtime
  `FileNotFoundException` is for **two** companion Pro DLLs by the same author, neither bundled nor
  downloaded: `System.Deps` (9 types: `Infobase` licensing/`pcid`, `Antispy`, `Imgur`, …) and a
  second assembly named `System.Dеps` with a **Cyrillic "е" (U+0435)** — a look-alike evasion
  trick — holding `CleanerPanel`/`Hardware`. The two encrypted `payload1` blobs (`nfH9PMep…`,
  67,280 B + 35,240 B) are strongly indicated to be these two Pro assemblies in AES-grade encrypted
  form, decrypted only by the Pro build's protector (see `report/FINAL_REPORT.md` §3/§3.1).
- **8 subsystems mapped** (privacy/telemetry registry tweaks, services, scheduled tasks/persistence,
  outbound network, context-menu/shell, disk cleanup, Defender control, "Personal recommendations").
  All persistence is user-facing; "Personal recommendations" is a fully-local, opt-in, reversible
  tweak engine.

### Indicators / notable behaviors (IOCs)

**Network (all decoded from the encrypted string table):**
- `win10tweaker.com/InfoChecker.php?key=imageres|imageres11|imgurup|uploadee` — server-directed URL
  resolver; the app then downloads vendor binaries **without signature/hash verification**.
- `win10tweaker.com/Reactivator.php?pcidOnly=<pcid>&email=<email>` — license phone-home.
- `myexternalip.com/raw`, `api.imgur.com/3/upload.xml` (public Client-ID `7476316c320ba07`),
  `virustotal.com/vtapi/v2/...` (user's own API key), WindowsSpyBlocker `spy.txt` (GitHub),
  `download.microsoft.com` (installers).

**Server-directed unsigned helper binaries** (the main supply-chain concern — see
[`report/FINAL_REPORT.md`](report/FINAL_REPORT.md) §S4a). `InfoChecker.php?key=<X>` returns a URL
chosen by the vendor's server at runtime; the app then `DownloadFile`s it with **no signature/hash
check** and drops it into a protected directory:

| InfoChecker key | Dropped to | Role |
|---|---|---|
| `imgurup` | `C:\Windows\imgurUp.exe` | "UploadOnImgur" right-click handler for image files |
| `uploadee` | `C:\Windows\Uploadee.exe` | "Upload.ee" right-click handler for all files |
| `imageres` / `imageres11` | `C:\Windows\System32\imageres.dll` / `SystemResources\imageres.dll.mun` | Custom icon DLL that **overwrites the protected system icon-resource DLL**, then restarts Explorer |

The two EXEs run only when the user invokes the context-menu verb (not auto-executed); the DLL is
loaded as an icon resource. Not an active backdoor in this build, but a supply-chain/integrity
surface. Benign in-source helpers (not server-fetched): `C:\Windows\SafeMode.vbs`,
`C:\Windows\Rebofresh.vbs`.

**Persistence:**
- Scheduled task `Win 10 Tweaker (AntiSpy)` → runs the tool's own exe with `AntiSpyRulesUpdater`
  (see [`evidence/antispy_task_template.xml`](evidence/antispy_task_template.xml)).
- On-logon task for the user's "add program to startup" feature.

**Security-weakening:**
- `ServerCertificateValidationCallback => true` (trust-all TLS) before fetching blocklists.
- User-selectable full **Windows Defender removal** and **Edge force-uninstall**.

---

## Repository layout

```
report/        Final verdict, subsystem map, per-subsystem deep-dives
evidence/      Decoded string table, AntiSpy task XML, Rebofresh.vbs (behavioral artifacts)
toolchain/     The original tooling built to unpack & deobfuscate the sample
```

Key documents:
- [`report/FINAL_REPORT.md`](report/FINAL_REPORT.md) — verdict + evidence + residual risk
- [`report/SUBSYSTEM_MAP.md`](report/SUBSYSTEM_MAP.md) — the 8 subsystems at a glance
- [`report/subsystem_network.md`](report/subsystem_network.md) — every outbound call traced
- [`report/subsystem_personal_recommendations.md`](report/subsystem_personal_recommendations.md)
- [`report/ANALYSIS_CONTEXT.md`](report/ANALYSIS_CONTEXT.md) — shared context/notation used in analysis

---

## The toolchain (how it was unpacked)

The protection required a custom pipeline. All source is under [`toolchain/`](toolchain/); see
[`toolchain/README.md`](toolchain/README.md) for per-tool usage.

1. **`dumper/Dumper.cs`** — a Harmony-instrumented host that runs the sample with UI suppressed and
   `Exit`/`FailFast` patched, force-JITs every method, and dumps IL via `GetMethodBody()`; also reads
   the ConfuserEx string blob straight from the `<Module>` static `byte[]` field at runtime.
2. **`rebuilder/`** — dnlib tool that reconstructs a decompilable `koi_fixed.netmodule` from the
   dumped IL + EH clauses (7,674 methods restored, `KeepOldMaxStack`).
3. **`string-decryptor/decode_strings.py`** — offline reimplementation of the 5 ConfuserEx string
   decryptors: `id' = (key*MUL)^XOR; offset=(id' & 0x3FFFFFFF)<<2; record=[u32 len][utf8]`.
4. **`readable-gen/make_readable.py`** — inlines decoded strings into the decompilation and renames
   zero-width identifiers to stable `zwNNNN`, producing the analysis-grade `koi_readable.cs`.
5. **`resdump/ResDump.cs`** — extracts the embedded `.resources` bundle (AntiSpy task XML, VBS, icons).
6. **`strhost/`, `pereader/`, `ilprint/`, `helpers/`** — supporting probes (string host, PE/metadata
   validation, IL printing, header/dependency hunting).

Decompilation of the rebuilt module was done with [ILSpy](https://github.com/icsharpcode/ILSpy)
`ilspycmd`; runtime instrumentation uses [Lib.Harmony](https://github.com/pardeike/Harmony);
module reconstruction uses [dnlib](https://github.com/0xd4d/dnlib).

---

## What is not published, and why

Deliberately **excluded** from this repository:
- **The sample binary and all unpacked/derived binaries** (`w10t.exe`, `koi*.netmodule`,
  `payload1.dll`, memory dumps). Redistributing a PUP/hacktool is unsafe and unnecessary — the
  hashes above uniquely identify it.
- **The full decompiled source** (`koi_readable.cs`, `koi_fixed_decompiled.cs`, ~38 MB). This is a
  reproduction of a commercial product's code; publishing it wholesale raises copyright concerns and
  is not needed to convey the analysis. The decoded **string table** (`evidence/string_map.tsv`) is
  included instead, as it is the behavioral evidence (URLs, registry paths, commands).
- **Machine-specific artifacts** (registry security-descriptor backup, runtime logs).

If you need the raw artifacts for verification, re-run the toolchain against your own copy of the
sample (identified by the hashes above).

---

## Disclaimer

This repository is defensive security research. The analyzed software is a third-party product of
its respective author; no affiliation is implied. Findings reflect the analyzed build (v20.5) only —
other versions may differ. Nothing here is an endorsement or an accusation of the vendor; it is a
technical assessment of one sample's observable behavior.
