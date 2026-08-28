# Win 10 Tweaker 20.5 — Subsystem Map

Source of truth: G:\projects\w10t_work\koi_readable.cs (decompiled + strings decoded).
Line numbers below are anchors in that file.

## Subsystems identified

### S1. Privacy / Telemetry disabling (registry)
Standard anti-telemetry tweaks. Decoded registry surface includes:
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` (AllowTelemetry etc.)
- `...\Windows\AppCompat` (DisableInventory, DisablePCA, AITAgent)
- `...\Windows\AdvertisingInfo` (DisabledByGroupPolicy)
- `...\Windows\LocationAndSensors`
- `...\Windows\SQMClient`, Windows Error Reporting (`...\Windows\Windows Error Reporting`)
- `...\InputPersonalization`, `...\Siuf\Rules` (feedback frequency)
- `HKCU\...\IE10RecommendedSettingsNo` (line 39374)
- `ModRiskFileTypes` = .bat;.exe;.reg;.vbs;.chm;.msi;.js;.cmd (line 39393)
Status: mapped (benign tweaker surface). No covert behavior.

### S2. Services management
- "Services Backup" = .reg export of service `Start` values (seen in HKCU\Software\Win 10 Tweaker).
- `net stop/start NvTelemetryContainer`; NVIDIA telemetry.
- schtasks /change /disable for WinSAT, UpdateOrchestrator "Schedule Scan", Wininet CacheTask,
  NVIDIA NvTmMon/NvTmRepOnLogon, MemoryDiagnostic.
- serv29 hint: extra security services disabled alongside Defender.
Status: mapped (benign tweaker surface).

### S3. Scheduled tasks & persistence  [ANALYZED BY PARENT — CLOSED]
- `Win 10 Tweaker (AntiSpy)` task (line ~48047-48060): extracts embedded XML template to
  `System32\Tasks\Win 10 Tweaker (AntiSpy)`, substitutes Username / FullWin10TweakerPath /
  pdvalue(P|D) / daysvalue, then `schtasks /create /xml ... /f`.
  RECOVERED the actual XML template from the embedded resource bundle (embedded_res/xml.bin):
  `<Command>"FullWin10TweakerPath"</Command><Arguments>AntiSpyRulesUpdater</Arguments>`,
  RunLevel=HighestAvailable, CalendarTrigger daily (DaysInterval=daysvalue, Interval=pdvalue).
  => Runs the tweaker's OWN exe with arg AntiSpyRulesUpdater to refresh antispy hosts rules.
  Documented feature ("Automatically update antispyware rules every", line 59067). Self-update,
  NOT a foreign payload.
- Onlogon task (line ~83784-83899): part of the user's "add program to startup" manager.
  If selected file ends `.vbs` -> `schtasks /create /tn "<name> task" /sc onlogon
  /tr "wscript.exe '<file>'" /rl highest /f`; else runs the file directly. User-initiated.
- `C:\Windows\SafeMode.vbs` (line ~32849-33014): written in-source (transparent). Only runs
  `bcdedit /set {current} safeboot ...` + `shutdown -r` for SafeMode/CMD/Network/NormalReboot
  context-menu entries under This-PC CLSID {20D04FE0-...}. Benign.
- `C:\Windows\Rebofresh.vbs` (embedded_res/Rebofresh1.txt, 'Script by XpucT'): `ie4uinit -show /
  -ClearIconCache` (icon-cache refresh) or `shutdown -r`. Two embedded .lnk shortcuts
  (Обновить_оболочку=Refresh shell, Перезагрузка=Reboot) point to it. Benign.
Verdict S3: BENIGN (all user-facing features; no hidden payload).

### S4. Outbound network / telemetry / download-and-use  [AGENT: net — CLOSED]
Full report: reports/subsystem_network.md. Findings:
- InfoChecker.php is a URL-resolver. DownloadString(InfoChecker.php?key=X) returns a URL, then
  DownloadFile fetches it. Keys:
    imageres/imageres11 -> custom icon DLL written to System32\imageres.dll (Win10) or
      SystemResources\imageres.dll.mun (Win11), then Explorer restart. Overwrites a protected
      system file with vendor content (integrity concern, not code-exec).
    imgurup -> imgurUp.exe written to C:\Windows\imgurUp.exe + registered as "UploadOnImgur"
      context-menu verb for image files. NOT auto-run; runs only on user right-click.
    uploadee -> Uploadee.exe written to C:\Windows\Uploadee.exe + "Upload.ee" shell verb.
  => SERVER-DIRECTED, UNSIGNED vendor binaries dropped into system dirs, NO hash/sig check.
     Supply-chain surface (main security concern), but not an active backdoor in this build.
- Reactivator.php?pcidOnly=<pcid>&email=<email>: license phone-home (machine ID + email) to
  vendor; response stored to registry (Systems.h). Also runs `sc config seclogon start= demand`
  and a self-restart. pcid computed in MISSING System.Deps.dll (Infobase) — exact HWIDs unknown.
- myexternalip.com/raw: show public IP (feature).
- api.imgur.com/3/upload.xml: uploads screenshot of the app's own VT-results panel; hardcoded
  public Imgur Client-ID 7476316c320ba07. User-initiated.
- virustotal.com vtapi/v2/file/scan|report: user-dragged file scan using the USER'S OWN API key
  (read from registry, not embedded).
- WindowsSpyBlocker spy.txt (GitHub): hosts entries + netsh firewall block rules. Installs a
  TRUST-ALL TLS callback (line 28857) first — weakens transport security.
- download.microsoft.com dxwebsetup.exe + NDP472-KB4054531-Web.exe: DownloadFile -> Process.Start
  (zw2147). ONLY download->execute path; genuine Microsoft installers, user-initiated.
- NO Assembly.Load/reflection/LOLBin/script-host of downloaded bytes. No raw IPs/ftp/onion/C2.
Verdict S4: SUSPICIOUS (low-conf) — supply-chain + TLS-bypass + opaque pcid, but NO backdoor/
  RAT/exfiltration/miner. Functionally a tweaker.

### S5. Context menu & shell extensions
- UploadOnImgur, CopyImageToClipboard, file hash (`powershell -windowstyle hidden get-filehash`),
  SafeMode boot menu (S3), ShellNew .cmd/.reg/.vbs entries (34225,58213), imageres.dll/.mun swap
  (15716) for custom icons.
Status: mapped (benign).

### S6. Disk cleanup & optimization
- Browser caches (Opera/Brave/Steam), temp, WebCache, CLR UsageLogs, winevt Logs, DriverStore\Temp,
  CryptnetUrlCache, wbem\Logs, RtBackup (lines 22070-23911).
- Windows Defender cache/history/Definition Updates cleanup (22632,24644,24772).
- RAM cleanup / EmptyWorkingSet (psapi), compression (System.Deps.Compress).
Status: mapped (benign).

### S7. Windows Defender / SmartScreen control  [ANALYZED BY PARENT]
- "Stop and disable Windows Defender and SmartScreen" (System3, line 58645/58991) — documented,
  with explicit warning not to use with Edge/Store.
- Reads `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`=="1" (61881);
  writes/deletes Defender policy values incl. SpynetReporting, SubmitSamplesConsent (142816-142840).
- "PersonalDefender" recommendation: remove Defender fully to free space (58909).
Verdict S7: aggressive but USER-SELECTED and documented. Not covert.

### S8. Personal recommendations  [AGENT: rec]
Pro-feature panel (PersonalPanel/FlowPanel). Report: reports/subsystem_personal_recommendations.md

## Companion dependency
- `System.Deps.dll` (same author, PublicKeyToken 0e4c2d2ea0ee1b44) NOT bundled in sample.
  Namespace System.Deps classes referenced: Infobase, AboutWindow, BlueFolder, Systems, RAM,
  Antispy, Imgur, Uploadeee, Compress. Its absence caused the runtime FileNotFoundException.
  Cannot be analyzed from this sample; referenced usage is consistent with legitimate features.

## Reputation
- MS detects HackTool:Win32/Win10Tweaker!MSR (hacktool/PUP class, not trojan).
- Heavy packing (.NET Reactor + ConfuserEx) is consistent with a commercial/paid "Pro" tool
  protecting itself, not necessarily malicious intent.
