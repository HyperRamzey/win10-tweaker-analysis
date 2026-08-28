# Toolchain

Original tooling built to unpack and deobfuscate the Win 10 Tweaker v20.5 sample. These are
research scripts, not polished products — most have **sample-specific hardcoded paths**
(`G:\projects\w10t_work\...`) that you must point at your own working directory / sample copy.

> Runtime instrumentation targets **.NET Framework 4.8** (`net48`) and was compiled with the
> framework `csc.exe`; the dnlib rebuilder and PE probes are small `net9.0` console projects.

## Pipeline order

```
dumper  ->  rebuilder  ->  (ILSpy decompile)  ->  string-decryptor  ->  readable-gen
                                                        ^
                                                   resdump (embedded resources, any time)
```

## Tools

### `dumper/Dumper.cs`
Harmony-instrumented host. Patches `Environment.Exit`/`FailFast`, `Assembly.Load(byte[])`,
`RuntimeAssembly.LoadModule`, and `Form.SetVisibleCore` (UI suppression); runs the module ctor and
the real entry point on an STA thread; force-JITs every method and dumps IL + EH clauses via
`GetMethodBody()`; reads the ConfuserEx string blob from the `<Module>` static field.
- Compile (example):
  `csc /target:exe /out:Dumper.exe /r:0Harmony.dll /r:System.Windows.Forms.dll Dumper.cs`
- Requires `0Harmony.dll` (Lib.Harmony) next to it; `Dumper.exe.config` keeps it on the modern CLR.
- Outputs: `dumped/method_il*.bin`, `dumped/string_blob_1.bin`, captured `load_*.bin` modules.

### `rebuilder/` (dnlib)
Rebuilds a decompilable module from the dumped IL. Reads `method_il.bin` + `method_il_module.bin`,
resolves methods by RID, reconstructs `CilBody` (with fat EH tables), sets `KeepOldMaxStack`, and
writes `koi_fixed.netmodule`.
- `dotnet run --project rebuilder` (restore dnlib 4.5.0 first).

### `string-decryptor/decode_strings.py`
Offline ConfuserEx string decryptor. Reads the runtime string blob + `string_keys.txt` (extracted
decryptor call-site keys) and emits `string_map.tsv` (`key<TAB>decoded`). The 5 decryptors'
`(MUL, XOR)` pairs are embedded in the script.
- `python decode_strings.py`

### `readable-gen/make_readable.py`
Post-processes the ILSpy decompilation: replaces decryptor calls with their decoded literals and
renames zero-width identifiers to stable `zwNNNN`, producing the analysis-grade `koi_readable.cs`.
- `python make_readable.py`

### `resdump/ResDump.cs`
Dumps a .NET binary `.resources` bundle (from `GetManifestResourceStream`) into its constituent
files (bytes/strings). Used to recover the AntiSpy task XML and helper VBS.
- `csc /target:exe /out:ResDump.exe ResDump.cs` then `ResDump.exe <bundle> <outdir>`

### `strhost/StrHost.cs`
Standalone host that loads the rebuilt module, runs its `<Module>` ctor, and invokes the string
decryptors directly (used to validate the offline decryptor against the live one).

### `pereader/`
Minimal `System.Reflection.Metadata.PEReader` probe to validate PE/metadata of dumped modules when
ILSpy refuses to open them (helped isolate that method bodies, not metadata, were the problem).

### `ilprint/`
Prints IL bodies/strings of selected methods from the rebuilt module (used to confirm decrypted IL
and to enumerate the `Apply*`/`Restore*` tweak handlers).

### `helpers/`
One-off investigation scripts: `hunt_headers.py` (scan for MZ/BSJB/records), `fieldrva_check.py`,
`deps_check*.py` (trace the `System.Deps` reference), `debug_names.py`, `show.ps1`.

## External dependencies
- [Lib.Harmony](https://github.com/pardeike/Harmony) — runtime method patching
- [dnlib](https://github.com/0xd4d/dnlib) — .NET metadata read/write
- [ILSpy / ilspycmd](https://github.com/icsharpcode/ILSpy) — decompilation
- Python 3 (`dnfile`, `pefile`, `pycryptodome` were used for early static triage)
