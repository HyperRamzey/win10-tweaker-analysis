# Win 10 Tweaker v20.5 — Malware Analysis & Verdict

**Sample:** `C:\Users\admin\Downloads\Win 10 Tweaker.exe` (copy: `G:\projects\w10t_work\w10t.exe`)
**SHA256:** `17938E0C5438006FD9BFCE2291F11545619F00D4EF459D6C851E419C321D61F4`
**MD5:** `917809BCE1896390C0BBA246FF481C48`
**Product:** Win 10 Tweaker 20.5 · Company "XpucT" (Russian tweaker, win10tweaker.ru / .com)
**Work dir:** `G:\projects\w10t_work`

---

## 1. Bottom-line verdict

**Win 10 Tweaker v20.5 is a legitimate (commercial, "Pro"-tier) Windows-10 tweaking utility, NOT
malware.** It is correctly classified by Microsoft as **HackTool:Win32/Win10Tweaker!MSR** — a
hacktool / potentially-unwanted-program class, not a trojan/backdoor/miner/stealer.

- **No miner, no credential stealer, no keylogger, no clipboard/screenshot harvester, no RAT/C2.**
- **No arbitrary remote-code download-and-execute.** The only download→execute path fetches genuine
  Microsoft installers (DirectX, .NET 4.7.2) from `download.microsoft.com`, user-initiated.
- **Real but limited security concerns** (why it is not "clean"): heavy commercial packing,
  server-directed download of unsigned helper EXEs into system directories, a trust-all-TLS
  callback, license phone-home of a machine ID + email, and user-selectable destructive tweaks
  (full Defender removal, Edge uninstall).

These concerns are consistent with an aggressive freemium tweaker, not with malicious intent.

---

## 2. Protection chain & how the code was recovered

The sample is double-protected; decompilation required a full unpacking pipeline:

1. **Outer: .NET Reactor / NecroBit.** Loader stub with virtualized/`extern` methods, encrypted
   payload in a random-named PE section (`;LkX;`), zeroed CLR resource RVA, and an externalized
   module named **`koi`**.
2. **Inner: ConfuserEx 1.7.0-alpha** on the `koi` module — control-flow flattening, zero-width
   identifier names, and an encrypted string table.

Recovery (all artifacts in `G:\projects\w10t_work`):
- Custom **Harmony dumper** (`Dumper.cs`) ran the app with UI suppressed and Exit/FailFast patched,
  force-JITed every method, and dumped IL via `GetMethodBody()` → `dumped/method_il.bin` +
  `method_il_module.bin` (the 11 `<Module>` methods).
- Runtime read of the ConfuserEx string blob from the `<Module>` static `byte[]` field →
  `dumped/string_blob_1.bin` (414,708 B).
- **dnlib rebuilder** (`rebuilder/`) reconstructed **`koi_fixed.netmodule`** (7,674 methods restored).
- ConfuserEx string decryptor reimplemented offline (`decode_strings.py`):
  `id' = (key*MUL) ^ XOR; offset=(id' & 0x3FFFFFFF)<<2; record=[u32 len][utf8]`; 5 decryptors →
  **9,315/9,320 keys decoded** → `string_map.tsv`.
- Final readable decompilation: **`koi_readable.cs`** (4.9 MB, literals inlined, zero-width names
  renamed `zwNNNN`). This is the file all subsystem analysis was done against.

---

## 3. The missing `System.Deps` dependency — resolved

`System.Deps` is a **companion DLL by the same author** (`System.Deps.dll`, same PublicKeyToken
`0e4c2d2ea0ee1b44`), loaded via `File.Exists(BaseDirectory + "\System.Deps.dll")` in
`Form1.Loader` (line 104495). It is **not bundled** in this single-file sample and is **never
downloaded** — hence the runtime `FileNotFoundException`. Its namespace holds 9 helper classes
referenced throughout `koi`: `Infobase, AboutWindow, BlueFolder, Systems, RAM, Antispy, Imgur,
Uploadeee, Compress`. A second AssemblyRef `System.Dеps` (Cyrillic "е") has zero TypeRefs — a
protector decoy. **Open item:** the exact hardware fingerprint `Infobase.pcid` (sent for license
activation) lives in this DLL; recovering it requires the vendor's full package.

---

## 4. Subsystem findings (8 subsystems)

Full detail: `SUBSYSTEM_MAP.md`, `reports/subsystem_network.md`,
`reports/subsystem_personal_recommendations.md`.

| # | Subsystem | Verdict |
|---|-----------|---------|
| S1 | Privacy/telemetry registry tweaks (DataCollection, AppCompat, AdvertisingInfo, WER, …) | Benign tweaker surface |
| S2 | Services management (Services Backup .reg, net stop/start, NVIDIA telemetry) | Benign |
| S3 | Scheduled tasks & persistence | **Benign** (all user-facing; see below) |
| S4 | Outbound network / telemetry / downloads | **Suspicious (low-conf)** — supply-chain surface, no backdoor |
| S5 | Context-menu & shell extensions (Imgur, copy-image, file-hash, SafeMode boot menu) | Benign |
| S6 | Disk cleanup & optimization (browser/Steam caches, temp, Defender cache, RAM) | Benign |
| S7 | Windows Defender / SmartScreen control | Aggressive but **user-selected & documented** |
| S8 | Personal recommendations | **Benign** (local, opt-in, reversible) |

### S3 persistence (verified, closed)
- `Win 10 Tweaker (AntiSpy)` task: recovered the embedded XML template (`embedded_res/xml.bin`) →
  runs the tweaker's **own** exe `"FullWin10TweakerPath" AntiSpyRulesUpdater`, HighestAvailable,
  daily — a self-update of antispy hosts rules. Not a foreign payload.
- Onlogon `wscript` task = the user's "add program to startup" manager (runs a user-chosen file).
- `C:\Windows\SafeMode.vbs` (transparent in-source): `bcdedit safeboot` + reboot context-menu.
- `C:\Windows\Rebofresh.vbs` + two `.lnk` shortcuts: icon-cache refresh / reboot. All benign.

### S4 network (verified, closed)

#### S4a. Server-directed unsigned helper binaries (the main supply-chain concern)
`InfoChecker.php?key=…` acts as a **server-directed URL resolver**. The app does
`DownloadString("https://win10tweaker.com/InfoChecker.php?key=<X>")`, which returns a plain-text
**URL**; a second `DownloadFile(<that URL>, <local path>)` then fetches the actual file. Because the
real download URL is chosen by the vendor's server at runtime (not hardcoded) and the downloaded
file is written to disk with **no Authenticode/hash verification**, the vendor — or anyone who
compromises `win10tweaker.com` or MITMs the connection (aided by the trust-all-TLS callback, S4c) —
can repoint these at arbitrary content at any time.

Three files are fetched this way and dropped into protected Windows directories:

| # | InfoChecker key | Dropped to | What it is / does |
|---|---|---|---|
| 1 | `key=imgurup` | `C:\Windows\imgurUp.exe` | EXE registered as the **"UploadOnImgur"** right-click handler for image files (`.jpg/.jpeg/.png/.gif/.bmp`). Command: `"C:\Windows\imgurUp.exe" "%1"` |
| 2 | `key=uploadee` | `C:\Windows\Uploadee.exe` | EXE registered as the **"Upload.ee"** right-click handler for all files (`HKCR\*\Shell\…`). Command: `"C:\Windows\Uploadee.exe" "%1"` |
| 3 | `key=imageres` (Win10) / `key=imageres11` (Win11) | `C:\Windows\System32\imageres.dll` / `C:\Windows\SystemResources\imageres.dll.mun` | A **DLL** (custom icon pack) that **overwrites the protected system icon-resource DLL**, then restarts Explorer. Loaded by Explorer as a resource, not executed as code. |

- The two EXEs are **not auto-executed** by the network code — they run only if the user invokes the
  context-menu verb. The DLL is loaded as an icon resource. So this is **not an active backdoor** in
  this build.
- It **is** a supply-chain/integrity surface: unsigned, server-directed binaries dropped into
  `C:\Windows`/`System32` and wired into the shell, with no signature/hash gate.
- Code anchors (`koi_readable.cs`): imgurup install `zw2688()` @ 41467 (download @ 41492);
  uploadee install `zw4159()` @ 63410 (download @ 63434); imageres download task `zw0871()` @ 15826,
  write `zw0876()`, Explorer restart @ 15820. Win10-vs-11 target switch @ 15712/15716.
  Full trace: [`subsystem_network.md`](subsystem_network.md) §1a–1c.

#### S4b. Other outbound endpoints

- `Reactivator.php?pcidOnly=<pcid>&email=<email>`: license phone-home (machine ID + email);
  response stored to registry. `pcid` computed in the missing `System.Deps.dll`.
- `myexternalip.com/raw` (show IP), `api.imgur.com` (user-initiated screenshot share, public
  Client-ID), `virustotal.com` (user's own API key), WindowsSpyBlocker `spy.txt` (hosts + netsh
  block rules), `download.microsoft.com` (installers). No raw IPs/ftp/onion/C2.

#### S4c. Trust-all TLS callback
A **trust-all TLS callback** (`ServerCertificateValidationCallback => true`, line 28857) is installed
before fetching the WindowsSpyBlocker lists — it disables certificate validation for the process's
downloads, weakening transport security and widening the S4a supply-chain surface (a MITM could
inject a malicious helper binary).

**Download→execute sweep:** the only DownloadFile→Process.Start chain fetches genuine Microsoft
installers (see S4b). **No** downloaded bytes reach `Assembly.Load`/reflection/LOLBin/script-host.

### S8 personal recommendations (verified, closed)
~30 contextual, opt-in tweaks built by a local `CommonMethod(label, ApplyN, RestoreN, …)` engine —
**fully local, no network, no System.Deps**. Each is a transparent hardcoded change (`powercfg`,
`bcdedit`, `dism`, `netsh`, registry), most reversible. Aggressive-but-user-chosen: full Defender
removal, Edge force-uninstall, TTL spoofing.

### Stealth-API sweep (parent, negative results)
No `SetWindowsHookEx`/`GetAsyncKeyState` keylogging; no LSASS/SAM/browser-credential access;
no clipboard monitoring; no screenshot capture in `koi` (that lives in missing `System.Deps.Imgur`).
`SeDebugPrivilege`/`AdjustTokenPrivileges` used for process/service control; `VaultSvc/NgcSvc/
NgcCtnrSvc` are service-management targets, not credential reads.

---

## 5. Why the heavy obfuscation?
.NET Reactor + ConfuserEx is consistent with a **paid "Pro" product protecting its code and license
check** (Reactivator/pcid, RSA license decryption, `key.txt`), not with hiding malicious payloads.
The packing is what triggers generic hacktool/AV heuristics.

## 6. Residual risk & recommendations
- **Supply-chain:** vendor can push unsigned `imgurUp.exe`/`Uploadee.exe`/`imageres.dll` to system
  dirs at any time via `InfoChecker.php`; combined with the TLS bypass, a compromised
  `win10tweaker.com` (or MITM) could deliver malicious binaries to users who enable those features.
- **Privacy:** license activation sends a machine fingerprint + email to the vendor.
- **Destructive tweaks:** users can irreversibly remove Defender/Edge; the tool warns but complies.
- **Recommendation:** treat as a PUP/hacktool. If used, disable the Imgur/Uploadee/imageres
  auto-fetch features and be cautious with Defender/Edge removal. To fully close the `pcid`
  question, obtain and analyze the vendor's `System.Deps.dll`.
- **Known gaps (closed as far as this sample allows):** (a) `System.Deps.dll` not bundled — `pcid`
  fingerprint unknown; (b) two encrypted resources inside the `payload1` container
  (`nfH9PMep…`, 67,280 B + 35,240 B) remain ciphertext (256/256 unique bytes) — decrypted on-demand
  by specific feature code, never loaded/executed during the monitored run, so not an active payload;
  (c) `load_02` capture is a 2 KB stub PE (protector placeholder), not a payload.

## 7. Artifact index
- `koi_readable.cs` — decompiled + string-decoded app (analysis source of truth)
- `koi_fixed.netmodule` / `koi_fixed.dll` — dnlib-rebuilt decompilable module
- `string_map.tsv`, `dumped/string_blob_1.bin` — decoded strings
- `SUBSYSTEM_MAP.md` — subsystem map
- `reports/subsystem_network.md`, `reports/subsystem_personal_recommendations.md`
- `embedded_res/` — extracted embedded resources (AntiSpy task XML, Rebofresh.vbs, .lnk)
- `ANALYSIS_CONTEXT.md` — shared analysis context
