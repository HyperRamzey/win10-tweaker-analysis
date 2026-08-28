# Win 10 Tweaker 20.5 — Analysis Context (shared with subagents)

## Sample
- Original: C:\Users\admin\Downloads\Win 10 Tweaker.exe
- Work dir:  G:\projects\w10t_work
- SHA256: 17938E0C5438006FD9BFCE2291F11545619F00D4EF459D6C851E419C321D61F4
- Product "Win 10 Tweaker" v20.5, Company "XpucT" (Russian tweaker, win10tweaker.ru)
- Protection: .NET Reactor/NecroBit (outer) + ConfuserEx 1.7.0-alpha (inner "koi" module)

## How the code was recovered (already done — do NOT repeat)
1. Custom Harmony dumper (Dumper.cs) ran the app, force-JITed all methods, dumped IL via
   GetMethodBody() -> dumped/method_il.bin + method_il_module.bin (the 11 <Module> methods).
2. Runtime string blob read from <Module> static byte[] field -> dumped/string_blob_1.bin (414708 bytes).
3. rebuilder/ (dnlib) rebuilt koi_fixed.netmodule + koi_fixed.dll (7674 methods restored).
4. ConfuserEx string decryptor reimplemented (decode_strings.py):
   id' = (key * MUL) ^ XOR ; offset = (id' & 0x3FFFFFFF) << 2 ; record = [u32 len][utf8]
   5 decryptors, constants per declaration order:
     dec0 (994551305, 0x5501E6A3)  dec1 (834812457, 0xB7B11)
     dec2 (-528178527, 0x4A2795E4) dec3 (-372400731, 0x42F5579)
     dec4 (663864581, -1969804901)
   9315/9320 keys decoded -> string_map.tsv
5. make_readable.py produced **koi_readable.cs** (4.9 MB, UTF-8):
   - all decryptor calls replaced with string literals
   - zero-width identifiers renamed to zwNNNN (stable)
   - ConfuserEx control-flow flattening (switch state-machines) still present but readable.

## Key files for analysis
- G:\projects\w10t_work\koi_readable.cs      <- THE decompiled app (analyze this)
- G:\projects\w10t_work\string_map.tsv       <- key -> decoded string
- G:\projects\w10t_work\dumped\string_blob_1.bin <- raw string table

## Established facts (verified)
- "System.Deps" is a COMPANION DLL (System.Deps.dll) by same author (same PublicKeyToken
  0e4c2d2ea0ee1b44), loaded via File.Exists(BaseDirectory+"\System.Deps.dll") in Form1.Loader.
  NOT bundled in our single-file sample -> caused the runtime FileNotFoundException.
  Namespace System.Deps has 9 helper classes referenced by koi:
    Infobase, AboutWindow, BlueFolder, Systems, RAM, Antispy, Imgur, Uploadeee, Compress
  A second AssemblyRef "System.Dеps" (Cyrillic e, U+0435) exists but has ZERO TypeRefs (decoy/
  protector artifact).
- NO miner indicators (stratum/xmrig/monero/etc = 0 hits).
- NO obvious credential stealer yet (needs confirmation).
- Outbound endpoints found (decoded):
    https://win10tweaker.com/InfoChecker.php?key=imageres|imageres11|imgurup|uploadee
    https://win10tweaker.com/Reactivator.php?pcidOnly=<pcid>&email=<email>   (line ~101486)
    https://myexternalip.com/raw   (line ~107748, shows external IP)
    https://api.imgur.com/3/upload.xml   (screenshot upload)
    https://www.virustotal.com/vtapi/v2/file/scan|report   (file scan feature)
    https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/{hosts,firewall}/spy.txt
    https://download.microsoft.com/.../NDP472-KB4054531-Web.exe , dxwebsetup.exe  (.NET/DX installers)
    https://win10tweaker.ru/* (site, forum, changelog, agreement, PayPal/Yandex donate)
- Registry tweak surface (decoded) = standard privacy/telemetry disabling:
    Policies\Microsoft\Windows\DataCollection, AppCompat, AdvertisingInfo, LocationAndSensors,
    SQMClient, Windows Error Reporting, Defender policies, Siuf\Rules, InputPersonalization, etc.
  + browser cache cleanup (Opera/Brave/Steam), context menu (UploadOnImgur, CopyImageToClipboard).
- Scheduled tasks:
    schtasks /change /disable for WinSAT, UpdateOrchestrator Schedule Scan, Wininet CacheTask,
      NVIDIA NvTmMon/NvTmRepOnLogon telemetry tasks, MemoryDiagnostic
    schtasks /create /tn "Win 10 Tweaker (AntiSpy)" /xml ...   (line ~48060)
    schtasks /create /tn "<name> task" /sc onlogon /tr "wscript.exe '<vbs>'" /rl highest /f
      (line ~83784-83822)  -> LOGON PERSISTENCE running a VBS at highest privilege.
- PowerShell: "powershell -windowstyle hidden -command (get-filehash ...)" = context-menu hash
  feature; PowerShell.Create() via System.Management.Automation used for tweaks.

## UI structure
- Form1 (class at line ~65842) with LeftMenu1..N nav, panels, Apply button.
- "Personal recommendations" panel: PersonalPanel / PersonalPanelPlate / FlowPanel,
  CloseRecommendations button. Localization key "PersonalRecomendations".
  Described (Pro feature list, line ~59141) as "Personal recommendations (bug fixes, unique features)".

## Conventions in koi_readable.cs
- global::<Module>."..." prefix on string literals is a decompiler artifact; treat as plain string.
- zwNNNN are renamed obfuscated helpers; many are trivial proxies (e.g. zw5790=File.Exists,
  zw5791=Path.Combine, zw5792=AppDomain.BaseDirectory, zw5793=AppDomain.CurrentDomain).
- Control-flow flattening: `while(true){ switch((num = f(num)) % N){ case k: ... } }`.
  Focus on the side-effecting statements (registry/service/process/network calls), ignore the
  state-machine arithmetic.
