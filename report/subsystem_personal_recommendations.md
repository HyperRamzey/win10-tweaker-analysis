# Subsystem Report — "PERSONAL RECOMMENDATIONS" feature

Sample: Win 10 Tweaker v20.5 (XpucT). Target: `G:\projects\w10t_work\koi_readable.cs`.
Line numbers refer to `koi_readable.cs`. (Report authored by parent agent after the delegated
`rec` run stalled; based on direct code tracing.)

## 1. Overview
"Personal recommendations" (localization key `PersonalRecomendations`) is a **Pro feature**
(blurb line 59141: "Personal recommendations (bug fixes, unique features)"). The tool inspects
the user's hardware/software configuration (desktop vs notebook, SSD present, default browser,
FastStone installed, Ryzen+Win11, etc.) and shows a list of *contextual, opt-in* tweaks, each
with an **Apply** and (usually) a **Restore** button.

UI: `PersonalPanel` (field 109305) contains `PersonalPanelHeaderPanel`, `PersonalPanelPlate`,
a `FlowPanel` that holds the recommendation rows, and a `CloseRecommendations` button.
Labels set at 102101-102103.

## 2. Mechanism (fully local, hardcoded)
Each row is created by a local helper:
```
121506  void CommonMethod(string text3, Action applyAction, Action restoreAction,
                          Color color, bool apply, bool restore)
```
Call sites (examples):
```
119338  CommonMethod(...PersonalDefender..., Apply3, this.Restore, blue, apply:true,  restore:false)
119835  CommonMethod(...PersonalHiberfil..., Apply9, Restore5,     blue, apply:true,  restore:false)
120106  CommonMethod(...PersonalTTL...,      Apply24, Restore20,   blue, apply:true,  restore:false)
119628  CommonMethod(...PersonalUP...,       Apply8,  null,        blue, apply:true,  restore:false)
```
The `ApplyN`/`RestoreN` handlers are **hardcoded local methods** (registry writes, `powercfg`,
`bcdedit`, `dism`, `netsh`, `schtasks`, `sc`). Irreversible items show a confirm dialog
(`PersonalWarning` = "This action cannot be undone. Are you fine with that?").

## 3. Data source: LOCAL — no network, no System.Deps
A scan of the whole recommendation-build region (lines ~118900-120600) for
`InfoChecker|DownloadString|DownloadFile|WebClient|http` returned exactly ONE hit, which is the
registry path `...\UrlAssociations\http\UserChoice` (default-browser detection), NOT a network
call. => The recommendations list and every action are entirely local. Nothing is fetched from
`InfoChecker.php` or `System.Deps.dll` for this feature.

## 4. Recommendation items -> exact system change
(~30 items; English labels from the localization block ~58900-59140.)

| Key | What it does (decoded) | Verified handler / change |
|---|---|---|
| PersonalDelayedAuto | Defer auto-start services for faster boot | Apply11: iterates service list, sets delayed-auto start |
| PersonalJPEG | Stop Windows lowering wallpaper quality | Apply2: `HKCU\Control Panel\Desktop\JPEGImportQuality=100` |
| PersonalBIO | Remove unused biometric drivers/modules (desktop) | device/driver removal |
| PersonalStorage | Disable Reserved Storage | `dism /online /set-reservedstoragestate /state:disabled` (Restore3 re-enables) |
| PersonalDefender | Completely remove Windows Defender (if already off) | Apply3; checks `HKLM\...\Windows Defender\DisableAntiSpyware==1` (61881) first |
| PersonalEdge | Uninstall Edge + services + schedulers | 96188 `...\Installer\setup.exe --uninstall --delete-profile --system-level --force-uninstall`; 96225 deletes EdgeUpdate tasks + `sc delete edgeupdate/edgeupdatem/MicrosoftEdgeElevationService` |
| PersonalUP | Enable hidden "Ultimate Performance" power plan | Apply8: `powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61` |
| PersonalHiberfil | Delete hibernation file (desktop+SSD) | Apply9: `powercfg -h off` (Restore5 `powercfg -h on`) |
| PersonalMTIA | Disable emoji process (battery/GPU) | disables emoji/TextInput process |
| Personal10minutes | Never turn off screen | Apply30: `powercfg /change monitor-timeout-ac 0` |
| Personal20minutes | Never power down disks | Apply10: `powercfg /change disk-timeout-ac 0` |
| PersonalNotebookWiFi | Stop random Wi-Fi power-off (laptop) | NIC power-management off |
| PersonalExplorerNetwork | Remove Explorer "Network" item | hides Network namespace |
| PersonalConcentration | Disable gaming notifications | Apply25: `...\Notifications\Settings\QuietHours\Enabled=0` |
| Personal11OldContextMenu | Win11: full context menu immediately | Win11 context-menu registry |
| Personal11RyzenPerfomance | Win11 Ryzen: disable TPM storage (+3%) | TPM/NGC storage tweak |
| PersonalEventlog | Minimize event-log size/count | shrinks log sizes |
| PersonalNumLock | Fix NumLock turning off | Apply13: `HKCU\Control Panel\Keyboard\InitialKeyboardIndicators=2` |
| Personal4096 | Bigger thumbnail cache | Apply12: `HKLM\...\Explorer\Max Cached Icons=4096` |
| PersonalTTL | Hide tethered mobile traffic from ISP | Apply24: sets `DefaultTTL` registry (120045) |
| PersonalTemp | Move Temp folder to drive root | redirects TEMP env (reboot required) |
| PersonalShift5 | Disable Sticky Keys (5x Shift) | Apply15: `HKCU\...\StickyKeys\Flags=506` |
| PersonalF8 | Enable F8 Safe Mode boot | Apply23: `bcdedit /set {default} bootmenupolicy legacy` (Restore19 `standard`) |
| PersonalFolderCMD | "Open command window here" | Apply16: adds `SOFTWARE\Classes\Directory\shell\cmd` |
| PersonalMSI | Extract/view MSI via context menu | MSI shell verb |
| PersonalNC | Disable Notification Center fully | Apply22: `...\Explorer\DisableNotificationCenter=1` + `...\PushNotifications\ToastEnabled=0` |
| PersonalLetsFinish | Disable "finish setting up your PC" nudge | disables OOBE nudge |
| PersonalDay | Show day-of-week in tray (with classic fonts) | Apply21: backs up + edits `HKCU\Control Panel\International\sShortDate` |
| PersonalDoNothing | Don't duck volume when mic used | Apply19: `HKCU\...\Multimedia\Audio\UserDuckingPreference=3` |
| PersonalFSCapture | Set FastStone Capture as image editor (if installed) | shell association |

Status/UI keys (not items): PersonalRecomendations, PersonalApplied, PersonalRestore,
PersonalWarning, PersonalHiberfilError, PersonalPanel*.

## 5. Beyond normal tweaking?
Most items are benign power-user conveniences. Three are aggressive but are explicit, documented,
user-clicked choices (not hidden):
- **PersonalDefender** — full removal of Windows Defender (irreversible; confirm dialog).
- **PersonalEdge** — force-uninstall of Microsoft Edge + its services/tasks.
- **PersonalTTL** — TTL spoofing to evade mobile-carrier tethering detection (arguably ToS-evasion,
  not malware).
None of these phone home, download anything, or run hidden code. All run only on explicit Apply.

## 6. Verdict — PERSONAL RECOMMENDATIONS: **BENIGN**
A local, context-aware, opt-in tweak engine. Every action is a transparent, hardcoded local system
change (registry / powercfg / bcdedit / dism / netsh / schtasks), most reversible via Restore.
No network fetch, no System.Deps involvement, no covert behavior. The only notable risks are the
user's own choice to apply destructive tweaks (Defender/Edge removal), which the tool warns about.
