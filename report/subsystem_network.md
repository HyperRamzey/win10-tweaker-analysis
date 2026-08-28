# Subsystem Report — OUTBOUND NETWORK / TELEMETRY / LICENSE / DOWNLOAD-AND-USE

Sample: Win 10 Tweaker v20.5 (XpucT), SHA256 `17938E0C…D61F4`
Target: `G:\projects\w10t_work\koi_readable.cs` (decompiled, deobfuscated strings; `zwNNNN` helpers; CFF flattening)
All line numbers refer to `koi_readable.cs` unless stated.

---

## 0. Executive summary

Every outbound network call in the sample was located and traced. The program talks to:

| # | Endpoint | Dir | Purpose | Executed? |
|---|----------|-----|---------|-----------|
| 1 | `win10tweaker.com/InfoChecker.php?key=imageres\|imageres11` | download | returns a **URL** for a custom `imageres.dll`/`.mun` icon pack | **NO** (written to disk, loaded as icon resource) |
| 2 | `win10tweaker.com/InfoChecker.php?key=imgurup` | download | returns a **URL** for `imgurUp.exe` helper | **NO** (written, registered as shell verb; not launched by network path) |
| 3 | `win10tweaker.com/InfoChecker.php?key=uploadee` | download | returns a **URL** for `Uploadee.exe` helper | **NO** (written, registered as shell verb) |
| 4 | `win10tweaker.com/Reactivator.php?pcidOnly=<pcid>&email=<email>` | download (GET) | license re-activation check | **NO** (response stored to registry) |
| 5 | `myexternalip.com/raw` | download | show user's public IP | NO |
| 6 | `api.imgur.com/3/upload.xml` | **upload** | uploads a screenshot (PNG) | NO |
| 7 | `virustotal.com/vtapi/v2/file/scan` + `/report` + `ui/files/<md5>/analyse` | **upload** + download | user-initiated file scan | NO |
| 8 | `raw.githubusercontent.com/…WindowsSpyBlocker/…/hosts/spy.txt` + `firewall/spy.txt` | download | telemetry-block lists → hosts file + netsh firewall rules | **Indirect** (data becomes `netsh` args — see §8) |
| 9 | `download.microsoft.com/…/dxwebsetup.exe` + `NDP472-KB4054531-Web.exe` | download | .NET/DX installers | **YES — DownloadFile → Process.Start** (§7) |
| 10 | `google.com/logos/doodles/…gif` | download | fake "speed test" bandwidth probe | NO |
| 11 | `win10tweaker.ru/*`, `google.com/search`, `bing.com`, `myip.ms`, `suggestqueries.google.com`, `microsoft.com/IEGallery` | browser / registry | help pages, donate links, IE search provider | NO |

**Download→execute confirmed only for the two Microsoft installers** (legitimate, signed Microsoft URLs, user-triggered "install .NET/DirectX" flow). No downloaded bytes are ever passed to `Assembly.Load`, reflection-invoke, `regsvr32/msiexec/rundll32`, `wscript/cscript`, or `powershell -enc`.

---

## 1. InfoChecker.php (keys imageres / imageres11 / imgurup / uploadee)

`InfoChecker.php` is a **URL-resolver / redirector**. The app does `DownloadString(InfoChecker.php?key=X)` which returns a plain-text **URL**, then does a second `DownloadFile(<that URL>, <local path>)`. The PHP itself only returns text; the *second* hop fetches the binary.

### 1a. imageres / imageres11 — custom icon DLL (class at 15708)

- URL property `zw0868` (15795–15816):
  - `if (!zw0861)` → `https://win10tweaker.com/InfoChecker.php?key=imageres11` (line 15810)
  - else → `https://win10tweaker.com/InfoChecker.php?key=imageres` (line 15815)
  - `zw0861` = `zw0862 < 22000` (line 15712) → i.e. **Win10 (build<22000) → `imageres`, Win11 → `imageres11`**.
- Target path `zw0863` (15716):
  - Win10: `zw0692.zw0865 + "\imageres.dll"` where `zw0692.zw0865 = Environment.SpecialFolder.System` = **`C:\Windows\System32\imageres.dll`**
  - Win11: `zw0692.zw0693 + "\SystemResources\imageres.dll.mun"` where `zw0693 = SpecialFolder.Windows` = **`C:\Windows\SystemResources\imageres.dll.mun`**
- `zw0871()` (15826) is the async download task; awaited from `Form1` at **75579** (`...zw0866.zw0871()`), invoked inside the "Apply" flow (`OpenDim(visible:true)` then download). `zw0875()` (15858) calls `zw0876(path)` for both targets (the actual write). `zw0869()` (15820) → `Process.Start("explorer")` (helper `zw0870`, 15937) to restart Explorer **after** the icon DLL is replaced.
- **Use:** the downloaded file replaces the system icon resource DLL. It is *loaded by Explorer as a resource*, not executed as code by this app. This is a theming feature ("custom icons"). Writing to `System32` requires admin (the app runs elevated).

**Verdict for 1a:** download → write to `System32\imageres.dll` → restart Explorer. Not code-execution of attacker bytes, but it *overwrites a protected system file with vendor-supplied content* — a integrity/tamper concern, not a backdoor.

### 1b. imgurup — `imgurUp.exe` (class `zw2666` at 41260)

- Field `zw2682` (41376): `zw0692.zw0693 + "\\imgurUp.exe"` = **`C:\Windows\imgurUp.exe`**.
- URL property `zw2687` (41457–41463): `https://win10tweaker.com/InfoChecker.php?key=imgurup`.
- Install method `zw2688()` (41467): if `!File.Exists(zw2682)` then:
  - `WebClient` with `User-Agent: W10T` (41490–41491)
  - **line 41492:** `zw2693(webClient, zw2694(webClient, zw2687), zw2682);`
    - `zw2694` = `DownloadString` (41706) → fetches the redirect URL from InfoChecker
    - `zw2693` = `DownloadFile` (41711) → downloads that URL to `C:\Windows\imgurUp.exe`
  - then registers shell context-menu verbs (41525–41531):
    - `HKCU\Software\Classes\SystemFileAssociations\{.jpg,.jpeg,.png,.gif,.bmp}\shell\UploadOnImgur` (list built 41648–41656)
    - `command` = `"C:\Windows\imgurUp.exe" "%1"` (41531)
- Triggered from `Form1` at **73800** (`zw2666.zw2685.zw2688()`) — part of enabling the "Upload on ImgBB" context menu. Removal at 125754 (`zw2700`).

**Verdict for 1b:** downloads an EXE to `C:\Windows\imgurUp.exe` and wires it as a right-click handler. The EXE is **not launched by the network code**; it runs only if the user invokes the context-menu verb. Still, it is a vendor-fetched binary dropped into a system directory — a persistence/supply-chain surface.

### 1c. uploadee — `Uploadee.exe` (class `zw4151` at 63329)

- URL property `zw4158` (63398–63406): `https://win10tweaker.com/InfoChecker.php?key=uploadee`.
- Install method `zw4159()` (63410): if `!File.Exists(zw0692.zw0693 + "\Uploadee.exe")` (i.e. **`C:\Windows\Uploadee.exe`**) then:
  - `WebClient`, `User-Agent: W10T` (63432–63433)
  - **line 63434:** `zw4165(webClient, zw4166(webClient, zw4158), zw4161(zw0692.zw0693, "\\Uploadee.exe"));`
    - `zw4166` = `DownloadString` (63580), `zw4165` = `DownloadFile` (63585)
  - registers `HKCR\*\Shell\<zw4155>\command` = `"C:\Windows\Uploadee.exe" "%1"` (63462–63463), label "Upload.ee".
- Triggered from `Form1` at **73540** (`zw4151.zw4156.zw4159()`); removal at 125781 (`zw4175`).

**Verdict for 1c:** identical pattern to 1b — vendor EXE dropped to `C:\Windows\`, registered as a shell verb, not auto-executed by the network path.

---

## 2. Reactivator.php — license phone-home (line 101486)

**Call site** (`<Purchase>d__192.MoveNext`, struct at 101338):

```
101486: awaiter = Methods.zw1884(
            zw5707("https://win10tweaker.com/Reactivator.php?pcidOnly=",
                   Infobase.pcid, "&email=", text)).GetAwaiter();
```
- `zw5707` = 4-arg string concat (101536). `Methods.zw1884` (29034) is an async `DownloadString` (returns `Task<string>`).
- `text` = the e-mail read from registry `Common.zw0119` value `"email"` (case 10u, 101470: `zw5705(zw5706(Common.zw0119,"email"))`).

**What is sent:** `pcidOnly=<Infobase.pcid>&email=<email>` — a GET with the machine's activation ID and the user's e-mail.

**How the response is used:** the returned string (`result`, case 17u 101421) is written back to the registry:
- case 2u (101456): `zw5704(Common.zw0119, Systems.l, Infobase.pcid)` → sets value `Systems.l` = pcid
- case 11u (101428): `zw5704(<>7__wrap2, <>7__wrap3, result)` → stores the server response under `Systems.h` (wrap3 = `Systems.h`, set at 101443). This is license-state persistence, not execution.
- Also runs `sc config seclogon start= demand` (101439) and a self-restart `Taskkill /f /im "<exe>" && Timeout /t 1 && "<exe>"` (101447–101453) as part of the (re)activation flow.

**Trigger:** `Form1.Purchase()` (125177) → `<Purchase>d__192`; called from `NewCheckResult` path (101233 `form.Purchase()`), itself driven by `zw2001()` (30690) at startup when an `email` value exists (30696, 30724 `zw1998.NewCheckResult(...)`), and from various "MakeOffer/buy" UI paths. So it fires on license purchase / re-activation, and at startup if a prior e-mail is stored.

### 2a. How `Infobase.pcid` is computed — **NOT in this module**

`Infobase` is a type in the **companion `System.Deps.dll`** (`using System.Deps;` line 9; loaded via `File.Exists(BaseDirectory+"\System.Deps.dll")` at 104495). `koi_readable.cs` only **references** `Infobase.pcid`; it does not define it. Exhaustive search of `koi_readable.cs`:

- `rg "pcid"` → only 6 hits, all **uses** of `Infobase.pcid` (23709, 67800, 101460, 101486, 122303) plus the URL literal. No assignment, no hardware-ID collection feeding it.
- Machine-identifier collection present in *this* module (for the SysInfo panel, not for pcid):
  - `SELECT * FROM Win32_BaseBoard` → `Manufacturer` + `Product` (28628, 94130) — motherboard, used for display.
  - `select * from Win32_DiskDrive` + `Win32_DiskDriveToDiskPartition` (95081, 95108) — disk info display.
  - `SELECT LastBootUpTime FROM Win32_OperatingSystem` (95675) — uptime display.
  - `Environment.UserName` (9032, 26632, …) — display/paths.
  - **No** `Win32_BIOS`, `MachineGuid`, `GetAdaptersInfo`/MAC, `GetVolumeInformation`/volume-serial, or `ProcessorId` queries exist in `koi_readable.cs`.

**Conclusion:** the hardware fingerprint (`pcid`) is computed inside `System.Deps.dll` (`Infobase` class), which is **not present in this single-file sample** (it is the missing companion DLL). From `koi_readable.cs` alone we can state: `pcid` is treated as an opaque activation/machine ID, compared against registry values (23709, 67800), written to `key.txt` on the Desktop (122303), and sent to `Reactivator.php`. **The exact identifiers (HWIDs/MAC/volume-serial) cannot be confirmed from this module** — that requires dumping `System.Deps.dll`.

**Verdict for §2:** license phone-home (machine ID + e-mail) to vendor server; response stored to registry. Not a backdoor; it is telemetry/licensing. The fingerprinting logic lives in the missing companion DLL.

---

## 3. myexternalip.com/raw (line 107748)

Inside `Form1.<SystemInfo>b__156_12` (async, struct 107681):
```
107748: Form1.zw5240((Control)_ip1, Form1.zw5871(Form1.zw5872(), "https://myexternalip.com/raw"));
```
- `zw5872` = `new WebClient()` (142101), `zw5871` = `DownloadString` (142106).
- **Purpose:** fetch the user's public WAN IP and display it in the SysInfo label `_ip1`. Immediately after (107785) it builds `https://myip.ms/info/whois/<ip>` for a "whois" link. Purely informational; the result is shown, not executed.

---

## 4. api.imgur.com/3/upload.xml (screenshot upload)

Inside `Form1.<Imgur>d__155.MoveNext` (struct 93340):
```
93378: HttpWebRequest obj = (HttpWebRequest)zw5349("https://api.imgur.com/3/upload.xml");
93379: Headers["Authorization"] = "Client-ID 7476316c320ba07";
93380: obj.Method = "POST";
93381: FileStream = File.Open(zw0692.zw1529 + "\" + form.scanVT);   // %TEMP%\<scanVT>
...    reads file, Base64-encodes it (zw5358 = Convert.ToBase64String, 93611),
93387: ContentType = "application/x-www-form-urlencoded";
93389: writes body to request stream;  93390: GetResponse()
```
- **Embedded credential:** Imgur **Client-ID `7476316c320ba07`** (line 93379). This is a public Imgur application Client-ID (not a secret), hardcoded for anonymous uploads.
- **What is uploaded:** the file `form.scanVT`. `scanVT` = localized `"VirusTotalPNG"` (108379). It is produced by `TakeScreenshot(i,k)` (118675) which **screenshots the app's own VirusTotal results panel** (`panelVT`) and saves it to `%TEMP%\<scanVT>` (118697), then calls `Imgur()` (118693 → 118773).
- **User-initiated?** Yes — it is the "share results" action tied to the VirusTotal panel UI (`PanelVT_Click` 118604, `Imgur()` 118773). The response XML is parsed for `<link>(.*?)</link>` (93496) and the link is put on the clipboard ("VirusTotalPNGClipboard" popup, 93460).
- **Direction:** UPLOAD (a PNG screenshot). No code execution of the response.

---

## 5. virustotal.com vtapi/v2/file/scan + /report (file scan feature)

Inside `Form1.<CheckOnVT>d__152` (struct 91487) and display class `<>c__DisplayClass152_0/1`:

- **Report lookup (download):**
  ```
  91939: <data>5__3 = zw5289(wc, "https://www.virustotal.com/vtapi/v2/file/report?apikey=" + form.APIKey() + "&resource=" + md5);
  ```
  (repeated at 92559). `zw5289` = `DownloadString` (93064). `md5` is the hash of the dropped file.
- **Submit for scan (upload):**
  ```
  91438: zw5272(wc, "https://www.virustotal.com/vtapi/v2/file/scan", "post", file);   // WebClient.UploadFile
  92150: same UploadFile call (retry path)
  ```
  `zw5272` = `UploadFile` (91478). Guarded by size check `< 33554432` (32 MB) at 92038; larger files show "VirusTotalLargeFile".
- **Re-analyse:** `92098: zw5296(wc, "https://www.virustotal.com/ui/files/" + md5 + "/analyse", "post", tmpfile)`.
- **API key:** **NOT embedded.** `form.APIKey()` (118492) reads registry value `"API Key"` from `Common.zw0119` (`HKCU\Software\Win 10 Tweaker`). The UI explicitly tells the user to paste **their own** VirusTotal API key (localization `TipVirusTotal`, 58523: "you'll need to get your own API Key on virustotal.com"; `APIVideo()` 118500 opens a help page). If no key is set the app shows the "get API key" offer (90816, 91026, 111084).
- **What files get scanned:** files the user **drag-and-drops** onto the app (`PanelVT_DragEnter` 118543, `CheckOnVT(file, reload)` 118641). This is an opt-in AV-check feature.
- **Response use:** the JSON is regex-parsed for `"positives":(.*?),` (92435) and rendered into the UI. Not executed.

**Verdict for §5:** legitimate, user-initiated VirusTotal integration using the user's own key. No embedded key, no execution.

---

## 6. WindowsSpyBlocker spy.txt (hosts / firewall)

Method `zw1863()` (28854), invoked from 36282 and 68914 (the "block telemetry/spy" tweak):

- Sets `ServicePointManager.SecurityProtocol = Tls12` (28856) and **installs a trust-all TLS callback** (28857: `ServerCertificateValidationCallback = (…) => true`, helper `zw1865` 29558). This disables certificate validation for subsequent downloads in the process — a security-weakening detail worth flagging.
- **hosts list (download):**
  ```
  28935: source = DownloadString("https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt").Split(\r\n, RemoveEmptyEntries)
  ```
  Filters out `### ` comment lines, merges with the existing hosts content, backs up the original hosts as `hosts (Original)` (28906), then **appends** the entries to `C:\Windows\System32\drivers\etc\hosts` (path built 28862; written via FileStream/StreamWriter 28940–28960).
- **firewall list (download → netsh):**
  ```
  29004: array3 = DownloadString("https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt").Split(...)
  28988: netsh advfirewall firewall delete rule name="<zw1631>"
  29014: netsh advfirewall firewall add rule name="<zw1631>" action=block dir=out remoteip=<comma-joined array3>
  ```
  The downloaded IP list is concatenated and passed as the `remoteip=` argument to `netsh` via hidden `cmd /c` (`zw0157`, 29141).

**Use:** this is the well-known open-source WindowsSpyBlocker telemetry blocklist. The downloaded text becomes (a) hosts-file entries and (b) `netsh` firewall block rules. It is **not executed as code**. This is an anti-telemetry feature (ironic for a "malware" analysis — it *blocks* Microsoft telemetry). Residual risk: remote text is fed into a `netsh` command line and into the hosts file without signature verification (supply-chain trust in the GitHub repo).

---

## 7. download.microsoft.com NDP472 / dxwebsetup — **DOWNLOAD + EXECUTE**

Two compiler-generated handlers in the "install prerequisites" form (class at 31829):

- **DirectX:**
  ```
  32443 private void zw2142() {
  32446   string text = zw2144(zw0692.zw1529, "\\DirectX.exe");        // %TEMP%\DirectX.exe
  32464   zw2146(webClient, "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe", text);  // DownloadFile
  32465   zw2147(text);                                                // Process.Start
  ```
- **.NET 4.7.2:**
  ```
  32478 private void zw2148() {
  32481   string text = zw2144(zw0692.zw1529, "\\NetFramework.exe");   // %TEMP%\NetFramework.exe
  32495   zw2146(webClient, "https://download.microsoft.com/download/0/5/C/05C1EC0E-D5EE-463B-BFE3-9311376A6809/NDP472-KB4054531-Web.exe", text); // DownloadFile
  32496   zw2147(text);                                                // Process.Start
  ```
- Helpers: `zw2146` = `DownloadFile` (32792), `zw2147` = `Process.Start` (32797), `zw2145` = `Form.Close` (32787).

**Trace: DownloadFile → Process.Start = CONFIRMED download-and-execute.** However:
- The URLs are **official `download.microsoft.com`** paths for the genuine DirectX Web Setup and .NET Framework 4.7.2 web installer.
- Trigger is a user-facing "install .NET/DirectX" action (the form at 31829 is reached from the "outdated .NET / missing DirectX" service prompts, localization `ServNetFramework` 58705 / `DirectXIsMissing` 58450).

**Verdict for §7:** download-and-execute is real but targets **legitimate Microsoft installers** on Microsoft's CDN, user-initiated. This is a standard "install prerequisite" pattern, not malware staging. (No hash/pinning is verified, so it trusts TLS to download.microsoft.com.)

---

## 8. CRITICAL — download→execute / backdoor sweep

I enumerated every network primitive and traced each returned payload:

**Network primitive call-sites (complete):**
- `DownloadString`: 29615 (SpyBlocker hosts), 41708 (imgurup redirect), 63582 (uploadee redirect), 93066 (VT report), 142108 (myexternalip), plus async `zw1884` (Reactivator, 29034). SpyBlocker firewall uses `zw1876` (29613) at 29004.
- `DownloadFile`: 32794 (MS installers), 41713 (imgurUp.exe), 63587 (Uploadee.exe).
- `DownloadData`: 105059 (`zw5802`) — the google doodle GIF "speed test" (104840).
- `UploadFile`: 91480 (`zw5272`, VT scan).
- `HttpWebRequest` POST: 93378 (Imgur upload).

**Fate of each downloaded payload:**
| Payload | Sink | Executed? |
|---|---|---|
| MS dxwebsetup/NDP472 | `%TEMP%\*.exe` → `Process.Start` (32465/32496) | **YES** (legit MS installers) |
| imgurUp.exe / Uploadee.exe | `C:\Windows\*.exe` + shell-verb registry | **NO** by network path (only on user context-menu use) |
| imageres.dll/.mun | `C:\Windows\System32\imageres.dll` / `SystemResources\…mun` | **NO** (loaded as icon resource by Explorer) |
| hosts/spy.txt | appended to `drivers\etc\hosts` | NO |
| firewall/spy.txt | `netsh … remoteip=` argument (29014) | NO (data-in-commandline, not code) |
| VT report JSON | regex-parsed → UI | NO |
| Reactivator response | registry `Systems.h` | NO |
| myexternalip/raw | UI label | NO |
| google doodle GIF | length used to compute Mbps (104856) | NO |

**Explicit negative results (searched, NOT found):**
- No `Assembly.Load`/`Assembly.LoadFrom`/`ReflectionOnlyLoad` on any downloaded byte. The only `Assembly.Load` is at **7500** (`zw0097 = Assembly.Load(zw0105(array))`) inside the ConfuserEx/protector **anti-tamper initializer** (`zw0101`, XOR-decrypts an embedded resource into the protector assembly) — it loads a **local, embedded** blob, not network data.
- No `regsvr32 /i http`, `msiexec /i http`, `rundll32 http`, `wscript/cscript` of downloaded scripts, `mshta`, `certutil -urlcache`, `bitsadmin`. (`rundll32` hits at 33092/33127/41203 are static Control_RunDLL/PhotoViewer context-menu verbs; `wscript` hits at 32987–33014 and 83809 reference a **locally-authored** `SafeMode.vbs`/logon VBS, not downloaded content — see persistence subsystem.)
- No `powershell -enc`/`-encodedcommand` on network content. (Hidden PowerShell present is `(get-filehash …)` context-menu and tweak scripting, per context file.)

**Base64 / dynamic-URI check (item 10):**
- `Convert.FromBase64String` appears once, at **141408** (`zw6133`), used only to base64-decode **license/license-hash strings** for RSA decryption in `Decrypt`/`Translate` (125108–125141) with the embedded RSA public key (30684). The output is a plaintext license string, **not executed**.
- `Convert.ToBase64String` at 9102 (`zw0202`) and 93613 (`zw5358`) — the latter Base64-encodes the screenshot **for upload** to Imgur. No decode-then-exec.
- Dynamic URIs are built only by string-concat of a decoded literal + runtime value (md5, ip, email, pcid, `{searchTerms}`). No URI is assembled from decoded base64 payloads.

**Conclusion of §8:** The only download→execute path is the two **Microsoft** installers. There is **no mechanism to fetch arbitrary remote code and run it** (no shellcode loader, no reflection exec, no script-host of downloaded scripts). The vendor-fetched `imgurUp.exe`/`Uploadee.exe`/`imageres.dll` are dropped to disk and registered/loaded, which is a supply-chain/integrity concern but not an active backdoor in this build.

---

## 9. Other hardcoded URLs / domains (item 9)

Full `https?://` sweep (`rg -oN` + uniq) — everything beyond the context-file list:

- `https://win10tweaker.ru/W10TServicesRu|En` (71142, 145251, …) — services reference page (WebBrowser).
- `https://win10tweaker.ru/W10TArgsRu|En` (145235, 145727, 146830) — launch-args doc page.
- `https://win10tweaker.ru/W10TVideoNotes` (145245, 145737) — video notes page.
- `https://win10tweaker.ru/changelog`, `/agreement`, `/forum/topic/`, `/forum/addtopic/7`, `/twikinarium/services/` — docs/forum.
- `https://win10tweaker.ru/PayPal`, `/Yandex` (10525, 12067, …) — donate links (opened in browser via `zw0379`).
- `https://win10tweaker.ru/files/APIru.mhtml|APIen.mhtml` (118533) — "how to get a VT API key" help page.
- `https://www.google.com/search?q=`, `http://www.google.com/search?hl=ru&q=` (46766, 67274, 92348) — "search the web for this error/term" links.
- `https://suggestqueries.google.com/complete/search?output=firefox&client=firefox&qu={searchTerms}` (39387) + `https://www.google.com/search?hl=ru&q={searchTerms}` (39388) + `https://www.google.com/favicon.ico` (39384) + `https://www.microsoft.com/en-us/IEGallery/GoogleAddOns` (39385) — written into the **registry** as an IE search-provider (`FaviconURL`/`OSDFileURL`/`SuggestionsURL_JSON`/`URL`), not fetched by the app.
- `https://www.bing.com` (39416) — set as IE Start Page in registry.
- `https://myip.ms/info/whois/` (107785) — whois link for the displayed IP.
- `https://google.com` (ping target) and `https://www.google.com/logos/doodles/2018/…gif` (104856) — bandwidth/ping "speed test".

**No** raw IPv4 endpoints, **no** `ftp://`, **no** `.onion`, **no** C2-looking domains. All domains are: vendor (`win10tweaker.com/.ru`), Microsoft, Google, Imgur, VirusTotal, GitHub (raw.githubusercontent), myexternalip.com, myip.ms. Nothing new beyond the context-file list except the browser/registry/doc links above.

---

## 10. Helper resolution (zwNNNN that matter)

| Helper | Meaning | Line |
|---|---|---|
| `zw2694`/`zw4166`/`zw1876`/`zw5289`/`zw5871` | `WebClient.DownloadString` | 41706/63580/29613/93064/142106 |
| `zw2693`/`zw4165`/`zw2146` | `WebClient.DownloadFile` | 41711/63585/32792 |
| `zw5802` | `WebClient.DownloadData` | 105057 |
| `zw5272` | `WebClient.UploadFile` | 91478 |
| `zw2147`/`zw0870` | `Process.Start` | 32797/15937 |
| `zw0157`/`zw1055` | hidden `cmd /c <arg>` | 29141/29151 |
| `zw1884` | async `DownloadString` (returns `Task<string>`) | 29034 |
| `zw1864`/`zw1865` | `ServicePointManager.SecurityProtocol` / trust-all `ServerCertificateValidationCallback` | 29553/29558 |
| `zw0692.zw0693` / `.zw0865` / `.zw1529` | `SpecialFolder.Windows` / `.System` / `%TEMP%` | 53976+ |
| `zw5358` | `Convert.ToBase64String` (Imgur upload) | 93611 |
| `zw6133` | `Convert.FromBase64String` (license RSA) | 141406 |

---

## 11. Verdict — OUTBOUND NETWORK subsystem: **SUSPICIOUS (low-confidence malicious), functionally a tweaker, not a backdoor**

**Evidence-based assessment:**

- **No malicious download-and-execute.** The only DownloadFile→Process.Start chain fetches **genuine Microsoft** installers (dxwebsetup, NDP472) from `download.microsoft.com`, user-initiated. No fetched bytes reach `Assembly.Load`, reflection, script hosts, or LOLBins.
- **No C2 / no arbitrary-code channel.** All endpoints are vendor, Microsoft, Google, Imgur, VirusTotal, GitHub, or IP-lookup services. No raw IPs, no ftp/onion, no encoded-payload URIs.
- **No credential/document exfiltration.** Uploads are (a) a user-dragged file to VirusTotal with the **user's own** API key, and (b) a screenshot of the app's own results panel to Imgur with a public Client-ID. Nothing sensitive leaves the machine covertly.
- **License telemetry present.** `Reactivator.php?pcidOnly=<pcid>&email=<email>` phones a machine activation ID + e-mail to the vendor. The hardware fingerprint (`pcid`) is computed in the **missing `System.Deps.dll`**, so its exact constituents (HWID/MAC/volume-serial) **cannot be confirmed from this module** — this is the main open question.
- **Integrity/supply-chain concerns (why it is not fully BENIGN):**
  1. `InfoChecker.php` acts as a remote URL resolver; the app then downloads vendor EXE/DLL helpers (`imgurUp.exe`, `Uploadee.exe`, `imageres.dll`) into `C:\Windows\`/`System32` with **no signature/hash verification** and registers them as shell verbs / system icon DLLs.
  2. A **trust-all TLS callback** is installed (28857) before downloading the SpyBlocker lists, weakening transport security.
  3. Remote text is fed into a `netsh` command line and the hosts file without validation.

**Net:** the network behavior is consistent with a commercial "tweaker" with aggressive auto-fetching of vendor helper binaries and license phone-home — **SUSPICIOUS** due to unverified vendor-binary download-into-system-dirs + disabled TLS validation + opaque machine fingerprint in the companion DLL, but **no evidence of backdoor/RAT/exfiltration/miner** in this subsystem.

**Open item for the parent:** dump/analyze `System.Deps.dll` (`Infobase.pcid`, `Infobase.Decrypt`, `Imgur`, `Uploadeee`, `Antispy`) to confirm exactly which hardware identifiers make up `pcid` and whether the companion DLL adds any network calls.
