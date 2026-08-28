using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;

// Rebuilds the NecroBit-protected 'koi' netmodule from the runtime IL dump
// produced by Dumper.exe (method_il.bin).
//
// Record format (little endian):
//   [u32 token][u32 ilLen][u16 maxstack][u32 localsTok][u32 ehCount|initLocals<<31]
//   { [u32 flags][u32 tryOff][u32 tryLen][u32 hndOff][u32 hndLen][u32 classTokOrFilterOff] x ehCount }
//   [IL bytes]

class Rec
{
    public uint Token;
    public ushort MaxStack;
    public uint LocalsTok;
    public bool InitLocals;
    public List<Eh> Ehs = new List<Eh>();
    public byte[] Il;
}

class Eh
{
    public uint Flags, TryOff, TryLen, HndOff, HndLen, Cls;
}

class Program
{
    static int Main(string[] args)
    {
        string input = args.Length > 0 ? args[0] : @"G:\projects\w10t_work\koi.netmodule";
        string ilDump = args.Length > 1 ? args[1] : @"G:\projects\w10t_work\dumped\method_il.bin";
        string output = args.Length > 2 ? args[2] : @"G:\projects\w10t_work\koi_fixed.netmodule";

        // 1) read the runtime IL dump(s)
        var recs = new Dictionary<uint, Rec>();
        ReadDump(ilDump, recs);
        string modDump = Path.Combine(Path.GetDirectoryName(ilDump), "method_il_module.bin");
        if (File.Exists(modDump)) ReadDump(modDump, recs);
        Console.WriteLine($"[rebuilder] IL dump records: {recs.Count}");

        // 2) load the module (metadata only; bodies are still encrypted at rest)
        var mod = ModuleDefMD.Load(input);
        Console.WriteLine($"[rebuilder] module {mod.Name}, types={mod.GetTypes().Count()}");

        int restored = 0, missing = 0, failed = 0;
        foreach (var type in mod.GetTypes())
        {
            foreach (var m in type.Methods)
            {
                if (m.Rid == 0) continue;
                if (!recs.TryGetValue(0x06000000u | m.Rid, out var r))
                {
                    if (m.RVA != 0)
                    {
                        missing++;
                        if (missing <= 20)
                            Console.WriteLine($"[rebuilder] no IL for rid={m.Rid} ({m.FullName}) - blanking body");
                        // blank body so decompilers don't choke on the encrypted bytes
                        m.Body = new CilBody();
                        m.Body.KeepOldMaxStack = true;
                    }
                    continue;
                }
                try
                {
                    byte[] extra = r.Ehs.Count > 0 ? BuildFatEhTable(r.Ehs) : null;
                    ushort flags = 0x03; // CorILMethod_Fat
                    if (r.InitLocals) flags |= 0x10;
                    if (extra != null) flags |= 0x08; // MoreSects
                    var body = MethodBodyReader.CreateCilBody(
                        mod, r.Il, extra, m.Parameters, flags,
                        r.MaxStack, (uint)r.Il.Length, r.LocalsTok,
                        default(GenericParamContext));
                    body.KeepOldMaxStack = true;
                    m.Body = body;
                    restored++;
                }
                catch (Exception ex)
                {
                    failed++;
                    if (failed < 10)
                        Console.WriteLine($"[rebuilder] failed rid={m.Rid}: {ex.Message}");
                }
            }
        }
        Console.WriteLine($"[rebuilder] restored={restored} missing={missing} failed={failed}");

        // 3) write the fixed module
        var opts = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(output, opts);
        Console.WriteLine($"[rebuilder] written: {output} ({new FileInfo(output).Length} bytes)");

        // 4) also emit a standalone assembly wrapper (koi_fixed.dll) so the module
        //    can be loaded directly with Assembly.Load for string decryption.
        string dllPath = Path.Combine(Path.GetDirectoryName(output), "koi_fixed.dll");
        var mod2 = ModuleDefMD.Load(File.ReadAllBytes(input));
        RestoreBodies(mod2, recs);
        var asmDef = new dnlib.DotNet.AssemblyDefUser("koi_fixed", new Version(1, 0, 0, 0));
        if (mod2.Assembly != null)
            mod2.Assembly.Modules.Remove(mod2);
        asmDef.Modules.Add(mod2);
        mod2.Kind = dnlib.DotNet.ModuleKind.Dll;
        var dllOpts = new dnlib.DotNet.Writer.ModuleWriterOptions(mod2);
        dllOpts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod2.Write(dllPath, dllOpts);
        Console.WriteLine($"[rebuilder] written: {dllPath} ({new FileInfo(dllPath).Length} bytes)");
        return 0;
    }

    static void RestoreBodies(ModuleDefMD mod, Dictionary<uint, Rec> recs)
    {
        foreach (var type in mod.GetTypes())
        {
            foreach (var m in type.Methods)
            {
                if (m.Rid == 0) continue;
                if (!recs.TryGetValue(0x06000000u | m.Rid, out var r))
                {
                    if (m.RVA != 0) m.Body = new CilBody { KeepOldMaxStack = true };
                    continue;
                }
                try
                {
                    byte[] extra = r.Ehs.Count > 0 ? BuildFatEhTable(r.Ehs) : null;
                    ushort flags = 0x03;
                    if (r.InitLocals) flags |= 0x10;
                    if (extra != null) flags |= 0x08;
                    var body = MethodBodyReader.CreateCilBody(
                        mod, r.Il, extra, m.Parameters, flags,
                        r.MaxStack, (uint)r.Il.Length, r.LocalsTok,
                        default(GenericParamContext));
                    body.KeepOldMaxStack = true;
                    m.Body = body;
                }
                catch { }
            }
        }
    }

    static void ReadDump(string path, Dictionary<uint, Rec> recs)
    {
        using (var fs = File.OpenRead(path))
        using (var br = new BinaryReader(fs))
        {
            while (fs.Position < fs.Length)
            {
                var r = new Rec();
                r.Token = br.ReadUInt32();
                uint ilLen = br.ReadUInt32();
                r.MaxStack = br.ReadUInt16();
                r.LocalsTok = br.ReadUInt32();
                uint ehc = br.ReadUInt32();
                r.InitLocals = (ehc & 0x80000000u) != 0;
                int n = (int)(ehc & 0x7FFFFFFFu);
                for (int i = 0; i < n; i++)
                {
                    r.Ehs.Add(new Eh
                    {
                        Flags = br.ReadUInt32(),
                        TryOff = br.ReadUInt32(),
                        TryLen = br.ReadUInt32(),
                        HndOff = br.ReadUInt32(),
                        HndLen = br.ReadUInt32(),
                        Cls = br.ReadUInt32()
                    });
                }
                r.Il = br.ReadBytes((int)ilLen);
                recs[r.Token] = r;
            }
        }
        Console.WriteLine($"[rebuilder] read {path}");
    }

    static byte[] BuildFatEhTable(List<Eh> ehs)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        int idx = 0, remaining = ehs.Count;
        while (remaining > 0)
        {
            int n = Math.Min(remaining, 42);
            int size = 4 + 24 * n;
            ushort header = (ushort)(0x40 | 0x01); // EHTable | FatFormat
            if (remaining > n) header |= 0x02;      // MoreSects
            header |= (ushort)((size / 4) << 8);
            bw.Write(header);
            bw.Write((ushort)0);
            for (int i = 0; i < n; i++, idx++)
            {
                var e = ehs[idx];
                bw.Write(e.Flags);
                bw.Write(e.TryOff);
                bw.Write(e.TryLen);
                bw.Write(e.HndOff);
                bw.Write(e.HndLen);
                bw.Write(e.Cls);
            }
            remaining -= n;
        }
        return ms.ToArray();
    }
}
