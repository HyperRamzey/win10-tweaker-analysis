using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using HarmonyLib;

static class Dumper
{
    static readonly string outDir = @"G:\projects\w10t_work\dumped";
    static readonly object logLock = new object();
    static int dumpIndex = 0;
    static int loadIndex = 0;

    static void Log(string s)
    {
        lock (logLock)
        {
            string line = "[" + DateTime.Now.ToString("HH:mm:ss.fff") + "] " + s;
            Console.WriteLine(line);
            File.AppendAllText(Path.Combine(outDir, "manifest.log"), line + Environment.NewLine);
        }
    }

    static string Sanitize(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s)
            sb.Append(char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_' ? c : '_');
        return sb.ToString();
    }

    // â”€â”€ Harmony prefixes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    public static bool BlockExit(int exitCode)
    {
        Log("[BLOCKED] Environment.Exit(" + exitCode + ") on thread " + Thread.CurrentThread.ManagedThreadId);
        throw new InvalidOperationException("EXIT_BLOCKED_" + exitCode);
    }

    public static bool BlockFailFast(string message)
    {
        Log("[BLOCKED] Environment.FailFast(\"" + message + "\") on thread " + Thread.CurrentThread.ManagedThreadId +
            " bg=" + Thread.CurrentThread.IsBackground + " name=" + Thread.CurrentThread.Name);
        if (Thread.CurrentThread.IsBackground)
        {
            // neutralize watchdog threads: freeze them forever
            while (true) Thread.Sleep(1000000);
        }
        throw new InvalidOperationException("FAILFAST_BLOCKED");
    }

    public static bool NoUIPrefix(ref bool value) { value = false; return true; }

    public static void CaptureAnyLoad(object[] __args)
    {
        if (__args == null) return;
        foreach (var a in __args)
        {
            var b = a as byte[];
            if (b != null && b.Length > 0) CaptureLoad(b);
        }
    }

    public static void CaptureAnyLoadPost(object[] __args)
    {
        if (__args == null) return;
        foreach (var a in __args)
        {
            var b = a as byte[];
            if (b != null && b.Length > 0) CaptureLoad(b);
        }
    }

    static readonly HashSet<string> capturedHashes = new HashSet<string>();

    public static void CaptureLoad(byte[] rawAssembly)
    {
        try
        {
            if (rawAssembly == null || rawAssembly.Length == 0) return;
            string h;
            using (var sha = System.Security.Cryptography.SHA256.Create())
                h = BitConverter.ToString(sha.ComputeHash(rawAssembly)).Replace("-", "");
            lock (capturedHashes)
            {
                if (capturedHashes.Contains(h)) { Log("[CAPTURE-DUP] skipped byte[" + rawAssembly.Length + "] sha=" + h.Substring(0, 12)); return; }
                capturedHashes.Add(h);
            }
            string fn = Path.Combine(outDir,
                string.Format("load_{0:D2}_{1}_bytes.bin", loadIndex++, rawAssembly.Length));
            File.WriteAllBytes(fn, rawAssembly);
            Log("[CAPTURE] Assembly.Load(byte[" + rawAssembly.Length + "]) -> " + Path.GetFileName(fn) +
                " head=" + BitConverter.ToString(rawAssembly, 0, Math.Min(4, rawAssembly.Length)) + " sha=" + h.Substring(0, 12));
        }
        catch (Exception ex) { Log("[!] CaptureLoad error: " + ex.Message); }
    }

    // â”€â”€ main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    static int Main(string[] args)
    {
        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "manifest.log"), "");
        Log("=== Dumper start, args: " + string.Join(" ", args));

        var harmony = new Harmony("w10t.dumper");

        harmony.Patch(
            typeof(Environment).GetMethod("Exit", BindingFlags.Public | BindingFlags.Static),
            prefix: new HarmonyMethod(typeof(Dumper).GetMethod("BlockExit")));

        foreach (var m in typeof(Environment).GetMethods(BindingFlags.Public | BindingFlags.Static))
            if (m.Name == "FailFast")
            {
                try { harmony.Patch(m, prefix: new HarmonyMethod(typeof(Dumper).GetMethod("BlockFailFast"))); }
                catch (Exception ex) { Log("[!] could not patch " + m + ": " + ex.Message); }
            }

        int patchedLoads = 0;
        foreach (var m in typeof(Assembly).GetMethods(BindingFlags.Public | BindingFlags.Static))
        {
            if (m.Name != "Load") continue;
            var ps = m.GetParameters();
            if (ps.Length >= 1 && ps[0].ParameterType == typeof(byte[]))
            {
                try { harmony.Patch(m, prefix: new HarmonyMethod(typeof(Dumper).GetMethod("CaptureLoad"))); patchedLoads++; }
                catch (Exception ex) { Log("[!] could not patch " + m + ": " + ex.Message); }
            }
        }
        foreach (var m in typeof(AppDomain).GetMethods(BindingFlags.Public | BindingFlags.Instance))
        {
            if (m.Name != "Load") continue;
            var ps = m.GetParameters();
            if (ps.Length == 1 && ps[0].ParameterType == typeof(byte[]))
            {
                try { harmony.Patch(m, prefix: new HarmonyMethod(typeof(Dumper).GetMethod("CaptureLoad"))); patchedLoads++; }
                catch (Exception ex) { Log("[!] could not patch " + m + ": " + ex.Message); }
            }
        }
        Log("[*] patched Assembly.Load overloads: " + patchedLoads);

        // patch every LoadModule-ish method (incl. internal RuntimeAssembly ones) that takes byte[]
        int patchedModules = 0;
        try
        {
            var targets = new List<Type> { typeof(Assembly), typeof(AppDomain) };
            var rtAsm = typeof(Assembly).Assembly.GetType("System.Reflection.RuntimeAssembly");
            if (rtAsm != null) targets.Add(rtAsm);
            var rtMod = typeof(Module).Assembly.GetType("System.Reflection.RuntimeModule");
            if (rtMod != null) targets.Add(rtMod);
            foreach (var t in targets)
            {
                foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {
                    if (!m.Name.Contains("LoadModule") && !m.Name.Contains("nLoad")) continue;
                    bool hasBytes = false;
                    foreach (var p in m.GetParameters()) if (p.ParameterType == typeof(byte[])) { hasBytes = true; break; }
                    if (!hasBytes) continue;
                    try {
                        harmony.Patch(m,
                            prefix: new HarmonyMethod(typeof(Dumper).GetMethod("CaptureAnyLoad")),
                            postfix: new HarmonyMethod(typeof(Dumper).GetMethod("CaptureAnyLoadPost")));
                        patchedModules++; Log("[*] patched " + t.Name + "." + m.Name);
                    }
                    catch (Exception ex) { Log("[!] could not patch " + t.Name + "." + m.Name + ": " + ex.Message); }
                }
            }
        }
        catch (Exception ex) { Log("[!] LoadModule sweep failed: " + RootMsg(ex)); }
        Log("[*] patched LoadModule variants: " + patchedModules);

        // suppress any WinForms UI so the tweaked app never shows windows on the desktop
        try
        {
            var svc = typeof(Form).GetMethod("SetVisibleCore", BindingFlags.NonPublic | BindingFlags.Instance);
            harmony.Patch(svc, prefix: new HarmonyMethod(typeof(Dumper).GetMethod("NoUIPrefix")));
            Log("[*] Form.SetVisibleCore patched - windows stay hidden");
        }
        catch (Exception ex) { Log("[!] UI patch failed: " + ex.Message); }

        AppDomain.CurrentDomain.AssemblyLoad += (s, e) =>
            Log("[ASSEMBLY-LOAD] " + e.LoadedAssembly.FullName + " loc=" + SafeLoc(e.LoadedAssembly));

        string target = Path.GetFullPath(args[0]);
        string baseDir = Path.GetDirectoryName(target);
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
        {
            var simple = new AssemblyName(e.Name).Name;
            foreach (var ext in new[] { ".dll", ".exe" })
            {
                var c = Path.Combine(baseDir, simple + ext);
                if (File.Exists(c)) { Log("[RESOLVE] " + c); return Assembly.LoadFrom(c); }
            }
            Log("[RESOLVE-MISS] " + e.Name);
            return null;
        };

        Log("[*] Loading target: " + target);
        Assembly asm;
        try { asm = Assembly.LoadFrom(target); }
        catch (Exception ex) { Log("[FATAL] LoadFrom failed: " + ex); return 2; }
        Log("[*] Loaded: " + asm.FullName);
        asm.ModuleResolve += (s, e) =>
        {
            Log("[MODULE-RESOLVE-EVENT] name=" + e.Name);
            return null; // let their handler (registered in cctor) handle it
        };

        // 1) run <Module> cctor FIRST (reactor bootstrap registers resolvers here)
        try
        {
            Log("[*] Running module constructor via RunModuleConstructor");
            RuntimeHelpers.RunModuleConstructor(asm.ManifestModule.ModuleHandle);
            Log("[*] Module cctor completed normally");
        }
        catch (Exception ex)
        {
            Log("[!] Module cctor exception: " + Flatten(ex));
        }

        // 2) enumerate types (triggers ModuleResolve for 'koi' etc.)
        Type[] types = new Type[0];
        try
        {
            types = asm.GetTypes();
            Log("[*] GetTypes OK: " + types.Length + " types");
        }
        catch (ReflectionTypeLoadException ex)
        {
            types = ex.Types ?? new Type[0];
            Log("[!] ReflectionTypeLoadException: got " + types.Length + " types; first loader exceptions:");
            int n = 0;
            foreach (var le in ex.LoaderExceptions)
            {
                if (le == null) continue;
                Log("    - " + le.GetType().Name + ": " + le.Message);
                if (++n >= 5) break;
            }
        }
        catch (Exception ex) { Log("[!] GetTypes failed: " + Flatten(ex)); }

        // 3) list modules
        try
        {
            foreach (Module m in asm.Modules)
                Log("[MOD] " + m.Name + " :: " + m.FullyQualifiedName + " :: " + m.ScopeName);
        }
        catch (Exception ex) { Log("[!] module enumeration failed: " + Flatten(ex)); }

        Thread.Sleep(2000);

        // 4a) run payload container cctors + harvest resolver delegates + invoke them
        try { SecondStage(asm); }
        catch (Exception ex) { Log("[!] SecondStage failed: " + Flatten(ex)); }

        // 4b) invoke the real entry point on an STA thread; decryptors run lazily during Main
        try { ThirdStage(asm); }
        catch (Exception ex) { Log("[!] ThirdStage failed: " + Flatten(ex)); }

        // 4c) post-Main: retry types + resource extraction
        try { SecondStage(asm); }
        catch (Exception ex) { Log("[!] SecondStage(post) failed: " + Flatten(ex)); }

        // 4d) force-JIT every method of the koi module and dump all method IL
        try { FourthStage(asm); }
        catch (Exception ex) { Log("[!] FourthStage failed: " + Flatten(ex)); }

        // 4e) invoke the ConfuserEx string decryptor for all keys used in the code
        try { FifthStage(asm); }
        catch (Exception ex) { Log("[!] FifthStage failed: " + Flatten(ex)); }

        // 4) dump every loaded assembly/module image
        DumpEverything();

        // 5) also run all type cctors? Only if requested (risky) â€” second pass flag "deep"
        if (args.Length > 1 && args[1] == "deep")
        {
            Log("[*] DEEP pass: running all type cctors...");
            foreach (var t in types)
            {
                if (t == null || t.ContainsGenericParameters) continue;
                try { RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
                catch (Exception ex) { Log("[cctor-fail] " + SafeName(t) + ": " + RootMsg(ex)); }
            }
            Thread.Sleep(1000);
            DumpEverything();
        }

        Log("=== Dumper finished");
        return 0;
    }

    static void DumpEverything()
    {
        foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
        {
            bool fromBytes;
            try { fromBytes = string.IsNullOrEmpty(a.Location); } catch { fromBytes = true; }
            if (fromBytes)
            {
                Log("[skip-dump] in-memory assembly (raw bytes captured at Load): " + a.FullName);
                continue;
            }
            Module[] mods;
            try { mods = a.GetModules(); }
            catch (Exception ex) { Log("[!] GetModules failed for " + a.FullName + ": " + RootMsg(ex)); continue; }
            foreach (var m in mods)
            {
                try { DumpModuleImage(m); }
                catch (Exception ex) { Log("[!] dump failed for module " + m.Name + ": " + ex.Message); }
            }
        }
    }

    [DllImport("kernel32.dll")]
    static extern UIntPtr VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    static long RegionSizeAt(IntPtr p)
    {
        try
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(p, out mbi, (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == UIntPtr.Zero)
                return 0;
            return mbi.RegionSize.ToInt64() - (p.ToInt64() - mbi.BaseAddress.ToInt64());
        }
        catch { return 0; }
    }

    static void DumpModuleImage(Module m)
    {
        IntPtr hInst;
        try { hInst = Marshal.GetHINSTANCE(m); }
        catch { Log("[skip] GetHINSTANCE threw for " + m.Name); return; }
        if (hInst == IntPtr.Zero || hInst == new IntPtr(-1))
        {
            Log("[skip] no HINSTANCE for module " + m.Name + " (dynamic?)");
            return;
        }
        long baseAddr = hInst.ToInt64();
        short mz;
        try { mz = Marshal.ReadInt16(new IntPtr(baseAddr)); }
        catch { Log("[skip] unreadable base for " + m.Name); return; }
        if (mz != 0x5A4D) { Log("[skip] no MZ at base for " + m.Name); return; }

        int peOff = Marshal.ReadInt32(new IntPtr(baseAddr + 0x3C));
        if (Marshal.ReadInt32(new IntPtr(baseAddr + peOff)) != 0x00004550)
        { Log("[skip] no PE sig for " + m.Name); return; }

        ushort nsec = (ushort)Marshal.ReadInt16(new IntPtr(baseAddr + peOff + 6));
        ushort optSize = (ushort)Marshal.ReadInt16(new IntPtr(baseAddr + peOff + 20));
        long opt = baseAddr + peOff + 24;
        ushort optMagic = (ushort)Marshal.ReadInt16(new IntPtr(opt));
        bool plus = optMagic == 0x20B;
        uint sizeOfHeaders = (uint)Marshal.ReadInt32(new IntPtr(opt + 60));
        int ddOff = plus ? 112 : 96;
        long cliDir = opt + ddOff + 14 * 8;
        uint cliRva = (uint)Marshal.ReadInt32(new IntPtr(cliDir));

        // read section headers
        long secTbl = baseAddr + peOff + 24 + optSize;
        var secs = new List<SecInfo>();
        for (int i = 0; i < nsec; i++)
        {
            long sh = secTbl + i * 40;
            byte[] nb = new byte[8]; Marshal.Copy(new IntPtr(sh), nb, 0, 8);
            var s = new SecInfo();
            s.Name = Encoding.ASCII.GetString(nb).TrimEnd('\0');
            s.VSize = (uint)Marshal.ReadInt32(new IntPtr(sh + 8));
            s.VA = (uint)Marshal.ReadInt32(new IntPtr(sh + 12));
            s.RawSize = (uint)Marshal.ReadInt32(new IntPtr(sh + 16));
            s.RawPtr = (uint)Marshal.ReadInt32(new IntPtr(sh + 20));
            secs.Add(s);
        }

        // detect flat (file) layout vs memory-mapped layout via the CLR header location.
        // The CLR header (IMAGE_COR20_HEADER) starts with cb == 72.
        bool flat = false;
        if (cliRva != 0)
        {
            try
            {
                long region = RegionSizeAt(new IntPtr(baseAddr));
                int vMem = (cliRva < region) ? Marshal.ReadInt32(new IntPtr(baseAddr + cliRva)) : -1;
                uint fileOffCli = 0; bool haveFileOff = false;
                foreach (var s in secs)
                {
                    uint span = Math.Max(s.VSize, s.RawSize);
                    if (cliRva >= s.VA && cliRva < s.VA + span)
                    { fileOffCli = s.RawPtr + (cliRva - s.VA); haveFileOff = true; break; }
                }
                int vFile = (haveFileOff && fileOffCli < region) ? Marshal.ReadInt32(new IntPtr(baseAddr + fileOffCli)) : -1;
                Log(string.Format("[LAYOUT] {0} cliRva={1} vMem={2} vFile={3} region={4}", m.Name, cliRva, vMem, vFile, region));

                // raw region dump + BSJB scan for forensic recovery
                try
                {
                    long scanLen = region > 0 ? Math.Min(region, 16 * 1024 * 1024) : 0;
                    if (scanLen > 0)
                    {
                        var raw = new byte[scanLen];
                        Marshal.Copy(new IntPtr(baseAddr), raw, 0, (int)scanLen);
                        string rawFn = Path.Combine(outDir, string.Format("raw_{0:D2}_{1}.bin", dumpIndex, Sanitize(m.Name)));
                        File.WriteAllBytes(rawFn, raw);
                        var hits = new List<int>();
                        for (int bi = 0; bi + 4 <= raw.Length; bi += 4)
                        {
                            if (raw[bi] == 0x42 && raw[bi + 1] == 0x53 && raw[bi + 2] == 0x4A && raw[bi + 3] == 0x42)
                                hits.Add(bi);
                        }
                        Log(string.Format("[RAWSCAN] {0} dumped {1} bytes; BSJB hits: {2}", m.Name, scanLen,
                            hits.Count == 0 ? "none" : string.Join(",", hits.ConvertAll(h => "0x" + h.ToString("X")).ToArray())));
                    }
                }
                catch (Exception rex) { Log("[!] rawscan failed: " + RootMsg(rex)); }

                if (vFile == 72) flat = true;
                else if (vMem == 72) flat = false;
                else
                {
                    // fallback: search for BSJB within 0x800 bytes of each candidate position
                    flat = ScanBsjbFlat(baseAddr, region, cliRva, haveFileOff ? fileOffCli : 0);
                }
            }
            catch { }
        }

        byte[] outBytes;
        if (flat)
        {
            uint fileSize = sizeOfHeaders;
            foreach (var s in secs)
                if (s.RawPtr + s.RawSize > fileSize) fileSize = s.RawPtr + s.RawSize;
            long region = RegionSizeAt(new IntPtr(baseAddr));
            if (region > 0 && fileSize > (uint)region) fileSize = (uint)region;
            outBytes = new byte[fileSize];
            Marshal.Copy(new IntPtr(baseAddr), outBytes, 0, (int)fileSize);
        }
        else
        {
            // rebuild file layout from memory image
            var headers = new byte[sizeOfHeaders];
            Marshal.Copy(new IntPtr(baseAddr), headers, 0, (int)sizeOfHeaders);
            uint fileOff = AlignUp(sizeOfHeaders, 0x200);
            int newSecTbl = peOff + 24 + optSize;
            var plan = new List<Tuple<SecInfo, uint, uint>>();
            foreach (var s in secs)
            {
                uint copy = Math.Min(s.VSize, s.RawSize != 0 ? s.RawSize : s.VSize);
                WriteU32(headers, newSecTbl + secs.IndexOf(s) * 40 + 16, AlignUp(copy, 0x200));
                WriteU32(headers, newSecTbl + secs.IndexOf(s) * 40 + 20, fileOff);
                plan.Add(Tuple.Create(s, copy, fileOff));
                fileOff += AlignUp(copy, 0x200);
            }
            var ms = new MemoryStream();
            ms.Write(headers, 0, headers.Length);
            while (ms.Length < AlignUp(sizeOfHeaders, 0x200)) ms.WriteByte(0);
            foreach (var p in plan)
            {
                var buf = new byte[p.Item2];
                try { Marshal.Copy(new IntPtr(baseAddr + p.Item1.VA), buf, 0, (int)p.Item2); } catch { }
                ms.Write(buf, 0, buf.Length);
                int pad = (int)(AlignUp(p.Item2, 0x200) - p.Item2);
                if (pad > 0) ms.Write(new byte[pad], 0, pad);
            }
            outBytes = ms.ToArray();
        }

        string fn = Path.Combine(outDir,
            string.Format("img_{0:D2}_{1}.exe", dumpIndex++, Sanitize(m.Name)));
        File.WriteAllBytes(fn, outBytes);
        Log("[DUMP] module=" + m.Name + " layout=" + (flat ? "flat" : "mem->file") +
            " size=" + outBytes.Length + " -> " + Path.GetFileName(fn));
    }

    // â”€â”€ second stage: payload cctors + resolver harvesting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    static readonly string[] ProbeNames = new string[]
    {
        "koi",
        "nfH9PMepLjwh8NXsII5tAiddN7pfJ+LQ6rASUExgWT90jAUG93Ei1fkMPvl0DOAQbZqM3dUd/9UMTZuxasWQk+Q1DqSSsw2wVZnVXoRc",
        "nfH9PMepLjyQ7zCDDKAGPcrvoZXaO4fSkD7QwrBkYIk71BRnhpkrrqkDTELPLHSg0PGivP9lsZFffF+fD36nUJHsHeIEfkHpMJm5Hwpc3A==",
        "Win_10_Tweaker.Form1.resources",
        "qurjORzRqFFaxuAUHQhvsxwsuqKN"
    };

    static void SecondStage(Assembly mainAsm)
    {
        // run module cctors of every newly loaded assembly (payload containers register resolvers)
        foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
        {
            if (a == mainAsm) continue;
            try
            {
                foreach (Module m in a.GetModules())
                {
                    try { RuntimeHelpers.RunModuleConstructor(m.ModuleHandle); }
                    catch (Exception ex) { Log("[payload-cctor-fail] " + a.FullName + "/" + m.Name + ": " + RootMsg(ex)); }
                }
            }
            catch { }
        }

        // harvest delegate fields
        var dels = new List<Delegate>();
        var ad = AppDomain.CurrentDomain;
        foreach (var f in typeof(AppDomain).GetFields(BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Public))
        {
            try
            {
                if (!typeof(Delegate).IsAssignableFrom(f.FieldType)) continue;
                var d = (Delegate)f.GetValue(ad);
                if (d == null) continue;
                Log("[DELEGATE] AppDomain." + f.Name + " -> " + Describe(d));
                foreach (var h in d.GetInvocationList()) dels.Add(h);
            }
            catch { }
        }
        foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
        {
            foreach (var f in a.GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Public | BindingFlags.FlattenHierarchy))
            {
                try
                {
                    if (!typeof(Delegate).IsAssignableFrom(f.FieldType)) continue;
                    var d = (Delegate)f.GetValue(a);
                    if (d == null) continue;
                    Log("[DELEGATE] asm(" + SafeName2(a) + ")." + f.Name + " -> " + Describe(d));
                    foreach (var h in d.GetInvocationList()) dels.Add(h);
                }
                catch { }
            }
        }

        // invoke each resolver-like delegate with probe names
        foreach (var d in dels)
        {
            var ps = d.Method.GetParameters();
            if (ps.Length != 2 || ps[1].ParameterType != typeof(ResolveEventArgs)) continue;
            foreach (var name in ProbeNames)
            {
                object r = null;
                try { r = d.DynamicInvoke(null, new ResolveEventArgs(name)); }
                catch (Exception ex) { Log("[RESOLVER] " + Describe(d) + "(\"" + Short(name) + "\") threw " + RootMsg(ex)); continue; }
                if (r == null) { Log("[RESOLVER] " + Describe(d) + "(\"" + Short(name) + "\") -> null"); continue; }
                Log("[RESOLVER] " + Describe(d) + "(\"" + Short(name) + "\") -> " + r);
                var ra = r as Assembly;
                if (ra != null)
                {
                    Log("[RESOLVER-ASM] " + ra.FullName);
                    foreach (Module m in SafeModules(ra))
                        Log("[RESOLVER-MOD] " + m.Name + " :: " + m.FullyQualifiedName);
                }
            }
        }

        // after resolvers ran, retry GetTypes on main assembly and pull manifest resources
        try
        {
            var types = mainAsm.GetTypes();
            Log("[SECOND] GetTypes now OK: " + types.Length);
            foreach (var t in types)
                Log("[TYPE] " + SafeName(t));
        }
        catch (ReflectionTypeLoadException ex)
        {
            Log("[SECOND] still ReflectionTypeLoadException; loader exc: " + (ex.LoaderExceptions != null && ex.LoaderExceptions.Length > 0 ? RootMsg(ex.LoaderExceptions[0]) : "?"));
        }
        catch (Exception ex) { Log("[SECOND] GetTypes: " + RootMsg(ex)); }

        // write full type inventory with escaped names
        try
        {
            var tb = new StringBuilder();
            foreach (var t in SafeTypes(mainAsm))
            {
                tb.Append(EscapeName(SafeName(t)));
                var methods = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly);
                tb.Append(" | methods=").Append(methods.Length);
                tb.AppendLine();
            }
            File.WriteAllText(Path.Combine(outDir, "types_inventory.txt"), tb.ToString());
            Log("[TYPES] inventory written: " + SafeTypes(mainAsm).Length + " types");
        }
        catch (Exception ex) { Log("[!] type inventory failed: " + RootMsg(ex)); }

        foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
        {
            try
            {
                foreach (var rn in a.GetManifestResourceNames())
                {
                    try
                    {
                        using (var s = a.GetManifestResourceStream(rn))
                        {
                            if (s == null) { Log("[RES-NULL] " + SafeName2(a) + " :: " + Short(rn)); continue; }
                            var ms = new MemoryStream();
                            s.CopyTo(ms);
                            var fn = Path.Combine(outDir, "res_" + Sanitize(Short(rn)) + "_" + ms.Length + ".bin");
                            File.WriteAllBytes(fn, ms.ToArray());
                            Log("[RES-DUMP] " + SafeName2(a) + " :: " + Short(rn) + " -> " + Path.GetFileName(fn));
                        }
                    }
                    catch (Exception ex) { Log("[RES-FAIL] " + Short(rn) + ": " + RootMsg(ex)); }
                }
            }
            catch { }
        }
    }

    static Module[] SafeModules(Assembly a)
    { try { return a.GetModules(); } catch { return new Module[0]; } }

    static Type[] SafeTypes(Assembly a)
    {
        try { return a.GetTypes(); }
        catch (ReflectionTypeLoadException ex) { return ex.Types ?? new Type[0]; }
        catch { return new Type[0]; }
    }

    static string EscapeName(string s)
    {
        if (s == null) return "<null>";
        var sb = new StringBuilder();
        foreach (var c in s)
        {
            if (c >= 32 && c < 127) sb.Append(c);
            else sb.Append("\\u" + ((int)c).ToString("X4"));
        }
        return sb.ToString();
    }

    static string SafeName2(Assembly a)
    { try { return a.GetName().Name; } catch { return "?"; } }

    static string Short(string s)
    { return s.Length <= 48 ? s : s.Substring(0, 24) + "..." + s.Substring(s.Length - 12); }

    static string Describe(Delegate d)
    {
        try { return d.Method.DeclaringType.FullName + "::" + d.Method.Name + (d.Target != null ? " [instance]" : " [static]"); }
        catch { return "?"; }
    }

    // â”€â”€ third stage: run the real Main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    static void FifthStage(Assembly mainAsm)
    {
        // Invoke the ConfuserEx string decryptor (<Module> generic method taking int)
        // for every key found in the decompiled source, and dump the key->string map.
        Log("[FIFTH] string decryptor stage");
        Module koi = null;
        var t1 = mainAsm.GetType("Win_10_Tweaker.Form1");
        if (t1 != null) koi = t1.Module;
        if (koi == null) { Log("[FIFTH] koi module not found"); return; }

        Type moduleType = null;
        var candidateMethods = new List<MethodInfo>();
        for (uint rid = 1; rid <= 30; rid++)
        {
            MethodBase mb = null;
            try { mb = koi.ResolveMethod((int)(0x06000000u | rid)); }
            catch (Exception ex) { if (rid <= 14) Log("[FIFTH] ResolveMethod rid=" + rid + " EX: " + ex.GetType().Name + ": " + ex.Message); continue; }
            if (mb == null) { if (rid <= 14) Log("[FIFTH] ResolveMethod rid=" + rid + " -> null"); continue; }
            string dtn = "<null>";
            try { if (mb.DeclaringType != null) dtn = mb.DeclaringType.Name; } catch { }
            if (rid <= 14) Log("[FIFTH] ResolveMethod rid=" + rid + " -> " + dtn + " :: " + mb.Name.Replace("\u200b", "").Replace("\u200c", "").Replace("\u200d", "").Replace("\u206a", "").Replace("\u206b", "").Replace("\u206c", "").Replace("\u206d", "").Replace("\u206e", "").Replace("\u206f", "").Replace("\u202a", "").Replace("\u202b", "").Replace("\u202c", "").Replace("\u202d", "").Replace("\u202e", ""));
            // methods owned by <Module> come back with a null DeclaringType
            if (mb.DeclaringType != null && mb.DeclaringType.Name != "<Module>") continue;
            if (mb.DeclaringType != null && moduleType == null) moduleType = mb.DeclaringType;
            var mi = mb as MethodInfo;
            if (mi == null) continue;
            string sig;
            try
            {
                var ps = mi.GetParameters();
                sig = (mi.IsGenericMethodDefinition ? "GEN " : "") + mi.ReturnType.Name + " (" +
                      string.Join(",", ps.Select(p => p.ParameterType.Name).ToArray()) + ")";
            }
            catch { sig = "?"; }
            Log("[FIFTH] <Module> rid=" + rid + " token=" + mi.MetadataToken.ToString("X8") + " " + sig);
            if (mi.IsGenericMethodDefinition)
            {
                var ps = mi.GetParameters();
                if (ps.Length == 1 && ps[0].ParameterType == typeof(int))
                    candidateMethods.Add(mi);
            }
        }
        if (moduleType != null) Log("[FIFTH] <Module> type via declaring: " + moduleType.FullName);
        MethodInfo decryptor = candidateMethods.FirstOrDefault();
        if (decryptor == null && moduleType != null)
        {
            var methods = moduleType.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            Log("[FIFTH] <Module> static methods via type: " + methods.Length);
            foreach (var m in methods)
            {
                if (m.IsGenericMethodDefinition)
                {
                    var ps = m.GetParameters();
                    if (ps.Length == 1 && ps[0].ParameterType == typeof(int))
                        decryptor = m;
                }
            }
        }
        if (decryptor == null) { Log("[FIFTH] no generic int->T decryptor found"); }
        else Log("[FIFTH] decryptor token: " + decryptor.MetadataToken.ToString("X8"));

        var keys = new List<int>();
        foreach (var line in File.ReadAllLines(@"G:\projects\w10t_work\string_keys.txt"))
        {
            int k;
            if (int.TryParse(line.Trim(), out k)) keys.Add(k);
        }
        Log("[FIFTH] keys to decrypt: " + keys.Count);

        var dec = decryptor == null ? null : decryptor.MakeGenericMethod(typeof(string));
        string mapFile = Path.Combine(outDir, "string_map.tsv");
        int ok = 0, fail = 0;
        if (dec != null)
        {
            using (var sw = new StreamWriter(mapFile, false, Encoding.UTF8))
            {
                foreach (var k in keys)
                {
                    try
                    {
                        var s = (string)dec.Invoke(null, new object[] { k });
                        sw.Write(k);
                        sw.Write('\t');
                        sw.WriteLine(s.Replace("\\", "\\\\").Replace("\t", "\\t").Replace("\r", "\\r").Replace("\n", "\\n"));
                        ok++;
                    }
                    catch { fail++; }
                }
            }
            Log("[FIFTH] decrypted ok=" + ok + " fail=" + fail + " -> " + mapFile);
        }

        // Also dump the <Module> method bodies (missed by FourthStage because
        // Module.GetTypes() excludes <Module>).
        // Dump the static byte[] blob field(s) of <Module> — the decrypted
        // string table (populated by the cctor in the real process).
        for (uint frid = 1; frid <= 10; frid++)
        {
            FieldInfo fi = null;
            try { fi = koi.ResolveField((int)(0x04000000u | frid)); } catch { continue; }
            if (fi == null || !fi.IsStatic) continue;
            if (fi.DeclaringType != null && fi.DeclaringType.Name != "<Module>") continue;
            try
            {
                var v = fi.GetValue(null);
                var b = v as byte[];
                if (b != null)
                {
                    string blobFile = Path.Combine(outDir, "string_blob_" + frid + ".bin");
                    File.WriteAllBytes(blobFile, b);
                    Log("[FIFTH] blob field rid=" + frid + " len=" + b.Length + " -> " + blobFile);
                }
                else
                {
                    Log("[FIFTH] field rid=" + frid + " type=" + fi.FieldType.Name + " value=" + (v == null ? "null" : v.GetType().Name));
                }
            }
            catch (Exception ex) { Log("[FIFTH] field rid=" + frid + " EX: " + ex.GetType().Name + ": " + ex.Message); }
        }

        string modIlFile = Path.Combine(outDir, "method_il_module.bin");
        var modMethods = new List<MethodBase>();
        for (uint rid = 1; rid <= 30; rid++)
        {
            MethodBase mb = null;
            try { mb = koi.ResolveMethod((int)(0x06000000u | rid)); } catch { continue; }
            if (mb != null && (mb.DeclaringType == null || mb.DeclaringType.Name == "<Module>"))
                modMethods.Add(mb);
        }
        if (moduleType != null)
        {
            try { if (moduleType.TypeInitializer != null) modMethods.Add(moduleType.TypeInitializer); }
            catch { }
        }
        using (var fs = File.Create(modIlFile))
        using (var bw = new BinaryWriter(fs))
        {
            int got = 0, none = 0, err = 0;
            foreach (var mb in modMethods)
            {
                int tok = 0;
                try { tok = mb.MetadataToken; } catch { continue; }
                try
                {
                    var body = mb.GetMethodBody();
                    var il = body == null ? null : body.GetILAsByteArray();
                    if (il == null) { none++; Log("[FIFTH] <Module> method " + tok.ToString("X8") + " has no body"); continue; }
                    var ehs = body.ExceptionHandlingClauses;
                    bw.Write(tok);
                    bw.Write(il.Length);
                    bw.Write((ushort)body.MaxStackSize);
                    bw.Write(body.LocalSignatureMetadataToken);
                    uint ehc = (uint)(ehs == null ? 0 : ehs.Count);
                    if (body.InitLocals) ehc |= 0x80000000u;
                    bw.Write(ehc);
                    if (ehs != null)
                    {
                        foreach (var eh in ehs)
                        {
                            uint cls = 0;
                            try
                            {
                                if (eh.Flags == ExceptionHandlingClauseOptions.Clause && eh.CatchType != null)
                                    cls = (uint)eh.CatchType.MetadataToken;
                                else if (eh.Flags == ExceptionHandlingClauseOptions.Filter)
                                    cls = (uint)eh.FilterOffset;
                            }
                            catch { }
                            bw.Write((uint)eh.Flags);
                            bw.Write(eh.TryOffset);
                            bw.Write(eh.TryLength);
                            bw.Write(eh.HandlerOffset);
                            bw.Write(eh.HandlerLength);
                            bw.Write(cls);
                        }
                    }
                    bw.Write(il);
                    got++;
                    Log("[FIFTH] <Module> method " + tok.ToString("X8") + " IL=" + il.Length);
                }
                catch (Exception ex) { err++; Log("[FIFTH] <Module> method " + tok.ToString("X8") + " EX: " + ex.Message); }
            }
            Log("[FIFTH] <Module> IL dump: got=" + got + " none=" + none + " err=" + err + " -> " + modIlFile);
        }
    }

    static void FourthStage(Assembly mainAsm)
    {
        Module koi = null;
        foreach (var m in SafeModules(mainAsm))
        {
            Log("[FOURTH] mainAsm module: " + m.Name);
            if (m.Name != null && m.Name.ToLower().Contains("koi")) koi = m;
        }
        if (koi == null)
        {
            var t1 = mainAsm.GetType("Win_10_Tweaker.Form1");
            if (t1 != null) koi = t1.Module;
        }
        if (koi == null)
        {
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
            {
                foreach (var m in SafeModules(a))
                {
                    int tc = 0;
                    try { tc = SafeTypes(a).Length; } catch { }
                    if (m.Name != null && m.Name.ToLower().Contains("koi")) { koi = m; break; }
                }
                if (koi != null) break;
            }
        }
        if (koi == null) { Log("[FOURTH] koi module not found"); return; }
        Log("[FOURTH] koi module found: " + koi.Name);

        Type[] types;
        try { types = koi.GetTypes(); }
        catch (ReflectionTypeLoadException ex) { types = ex.Types ?? new Type[0]; }
        Log("[FOURTH] koi types: " + types.Length);

        var allMethods = new List<MethodBase>();
        foreach (var t in types)
        {
            if (t == null) continue;
            try
            {
                foreach (var mb in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                    allMethods.Add(mb);
                foreach (var cb in t.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                    allMethods.Add(cb);
            }
            catch (Exception ex) { Log("[FOURTH] GetMethods failed for " + SafeName(t) + ": " + RootMsg(ex)); }
        }
        Log("[FOURTH] methods collected: " + allMethods.Count);

        // Phase A: ground truth for a few known tokens (RVA mapping known from metadata)
        foreach (uint tok in new uint[] { 0x06000004, 0x06000005, 0x06000006, 0x0600000B, 0x06000016 })
        {
            try
            {
                var mb = koi.ResolveMethod((int)tok) as MethodBase;
                if (mb == null) { Log("[GT] tok=" + tok.ToString("X8") + " resolve null"); continue; }
                var body = mb.GetMethodBody();
                if (body == null) { Log("[GT] tok=" + tok.ToString("X8") + " body null"); continue; }
                var il = body.GetILAsByteArray();
                Log(string.Format("[GT] tok={0} type={1} ilLen={2} maxstack={3} localsTok={4} il={5}",
                    tok.ToString("X8"), EscapeName(SafeName(mb.DeclaringType)),
                    il == null ? -1 : il.Length, body.MaxStackSize,
                    body.LocalSignatureMetadataToken,
                    il == null ? "-" : BitConverter.ToString(il, 0, Math.Min(16, il.Length))));
            }
            catch (Exception ex) { Log("[GT] tok=" + tok.ToString("X8") + " FAILED: " + RootMsg(ex)); }
        }

        // Phase B: force-JIT every method so the protector decrypts all bodies in place
        int ok = 0, fail = 0, skip = 0;
        foreach (var mb in allMethods)
        {
            try
            {
                if (mb.IsAbstract || mb.ContainsGenericParameters ||
                    (mb.DeclaringType != null && mb.DeclaringType.ContainsGenericParameters))
                { skip++; continue; }
                RuntimeHelpers.PrepareMethod(mb.MethodHandle);
                ok++;
            }
            catch { fail++; }
        }
        Log("[FOURTH] PrepareMethod ok=" + ok + " fail=" + fail + " skip=" + skip);

        // Phase C: dump IL + EH clauses of every method via GetMethodBody
        // Record: [u32 token][u32 ilLen][u16 maxstack][u32 localsTok][u32 ehCount]
        //         { [u32 flags][u32 tryOff][u32 tryLen][u32 hndOff][u32 hndLen][u32 classTokOrFilterOff] x ehCount }
        //         [IL bytes]
        string ilFile = Path.Combine(outDir, "method_il.bin");
        using (var fs = File.Create(ilFile))
        using (var bw = new BinaryWriter(fs))
        {
            int got = 0, none = 0, err = 0, ehTotal = 0;
            foreach (var mb in allMethods)
            {
                int tok = 0;
                try { tok = mb.MetadataToken; } catch { continue; }
                try
                {
                    if (mb.IsAbstract) { none++; continue; }
                    var body = mb.GetMethodBody();
                    var il = body == null ? null : body.GetILAsByteArray();
                    if (il == null) { none++; continue; }
                    var ehs = body.ExceptionHandlingClauses;
                    bw.Write(tok);
                    bw.Write(il.Length);
                    bw.Write((ushort)body.MaxStackSize);
                    bw.Write(body.LocalSignatureMetadataToken);
                    uint ehc = (uint)(ehs == null ? 0 : ehs.Count);
                    if (body.InitLocals) ehc |= 0x80000000u;
                    bw.Write(ehc);
                    if (ehs != null)
                    {
                        foreach (var eh in ehs)
                        {
                            uint cls = 0;
                            try
                            {
                                if (eh.Flags == ExceptionHandlingClauseOptions.Clause && eh.CatchType != null)
                                    cls = (uint)eh.CatchType.MetadataToken;
                                else if (eh.Flags == ExceptionHandlingClauseOptions.Filter)
                                    cls = (uint)eh.FilterOffset;
                            }
                            catch { }
                            bw.Write((uint)eh.Flags);
                            bw.Write(eh.TryOffset);
                            bw.Write(eh.TryLength);
                            bw.Write(eh.HandlerOffset);
                            bw.Write(eh.HandlerLength);
                            bw.Write(cls);
                            ehTotal++;
                        }
                    }
                    bw.Write(il);
                    got++;
                }
                catch { err++; }
            }
            Log("[FOURTH] IL dump: got=" + got + " none=" + none + " err=" + err + " ehClauses=" + ehTotal + " -> " + ilFile);
        }
    }

    static void ThirdStage(Assembly asm)
    {
        var ep = asm.EntryPoint;
        Log("[*] EntryPoint: " + (ep != null ? ep.ToString() : "null"));
        if (ep == null) return;
        int before = AppDomain.CurrentDomain.GetAssemblies().Length;
        var t = new Thread(() =>
        {
            try
            {
                object[] args = ep.GetParameters().Length == 1 ? new object[] { new string[0] } : new object[0];
                var ret = ep.Invoke(null, args);
                Log("[MAIN] returned: " + ret);
            }
            catch (Exception ex) { Log("[MAIN] exception: " + Flatten(ex)); }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.IsBackground = true;
        t.Name = "FakeMain";
        t.Start();
        for (int i = 1; i <= 25; i++)
        {
            Thread.Sleep(1000);
            int now = AppDomain.CurrentDomain.GetAssemblies().Length;
            if (now != before || i % 5 == 0)
                Log("[WAIT] " + i + "s assemblies=" + now);
            before = now;
        }
    }

    // â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    class SecInfo { public string Name; public uint VSize, VA, RawSize, RawPtr; }

    static bool ScanBsjbFlat(long baseAddr, long region, uint memPos, uint filePos)
    {
        foreach (var pos in new[] { memPos, filePos })
        {
            for (int delta = 0; delta < 0x800; delta += 4)
            {
                long p = pos + delta;
                if (p <= 0 || p + 4 > region) break;
                try
                {
                    if (Marshal.ReadInt32(new IntPtr(baseAddr + p)) == 0x42534A42)
                        return true; // BSJB reachable at file offset => flat layout
                }
                catch { break; }
            }
        }
        return false;
    }

    static uint AlignUp(uint v, uint a) { return (v + a - 1) / a * a; }

    static void WriteU32(byte[] buf, int off, uint v)
    {
        buf[off] = (byte)v; buf[off + 1] = (byte)(v >> 8);
        buf[off + 2] = (byte)(v >> 16); buf[off + 3] = (byte)(v >> 24);
    }

    static string SafeLoc(Assembly a)
    { try { return a.Location; } catch { return "<n/a>"; } }

    static string SafeName(Type t)
    { try { return t.FullName; } catch { return "<type>"; } }

    static string RootMsg(Exception ex)
    {
        while (ex.InnerException != null) ex = ex.InnerException;
        return ex.GetType().Name + ": " + ex.Message;
    }

    static string Flatten(Exception ex)
    {
        var sb = new StringBuilder();
        var cur = ex;
        int depth = 0;
        while (cur != null && depth < 4)
        {
            sb.Append(cur.GetType().Name + ": " + cur.Message + " | ");
            cur = cur.InnerException;
            depth++;
        }
        return sb.ToString();
    }
}


