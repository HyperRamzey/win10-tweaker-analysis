using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

// Loads the rebuilt koi_fixed.dll in a clean process (no NecroBit), runs the
// module cctor, then invokes the ConfuserEx string decryptor for every key.
static class StrHost
{
    static void Main(string[] args)
    {
        string dll = args.Length > 0 ? args[0] : @"G:\projects\w10t_work\koi_fixed.dll";
        string keysFile = args.Length > 1 ? args[1] : @"G:\projects\w10t_work\string_keys.txt";
        string outFile = args.Length > 2 ? args[2] : @"G:\projects\w10t_work\string_map.tsv";

        AppDomain.CurrentDomain.AssemblyResolve += (s, e) => null; // never pull external deps

        var bytes = File.ReadAllBytes(dll);
        var asm = Assembly.Load(bytes);
        var mod = asm.ManifestModule;
        Console.WriteLine("[host] loaded: " + asm.FullName + " module=" + mod.Name);

        // run the module cctor (initializes the string blob)
        try
        {
            RuntimeHelpers.RunModuleConstructor(mod.ModuleHandle);
            Console.WriteLine("[host] module cctor ran OK");
        }
        catch (Exception ex)
        {
            Console.WriteLine("[host] module cctor EX: " + ex.GetType().Name + ": " + ex.Message);
            var inner = ex.InnerException;
            while (inner != null)
            {
                Console.WriteLine("[host]   inner: " + inner.GetType().Name + ": " + inner.Message);
                Console.WriteLine(inner.StackTrace);
                inner = inner.InnerException;
            }
        }

        // find <Module> methods (DeclaringType == null)
        var decryptors = new List<MethodInfo>();
        Console.WriteLine("[host] <Module> fields:");
        for (uint frid = 1; frid <= 20; frid++)
        {
            FieldInfo fi = null;
            try { fi = mod.ResolveField((int)(0x04000000u | frid)); } catch { continue; }
            if (fi == null) continue;
            if (fi.DeclaringType != null && fi.DeclaringType.Name != "<Module>") continue;
            string val = "?";
            try
            {
                var v = fi.GetValue(null);
                if (v == null) val = "null";
                else
                {
                    var b = v as byte[];
                    var a = v as Array;
                    if (b != null) val = "byte[" + b.Length + "]";
                    else if (a != null) val = "Array[" + a.Length + "]";
                    else val = v.GetType().Name;
                }
            }
            catch (Exception ex) { val = "EX:" + ex.GetType().Name; }
            Console.WriteLine("[host]   field rid=" + frid + " type=" + fi.FieldType.Name + " static=" + fi.IsStatic + " value=" + val);
        }
        for (uint rid = 1; rid <= 30; rid++)
        {
            MethodBase mb = null;
            try { mb = mod.ResolveMethod((int)(0x06000000u | rid)); }
            catch { continue; }
            if (mb == null) continue;
            if (mb.DeclaringType != null && mb.DeclaringType.Name != "<Module>") continue;
            var mi = mb as MethodInfo;
            if (mi != null && mi.IsGenericMethodDefinition)
            {
                var ps = mi.GetParameters();
                if (ps.Length == 1 && ps[0].ParameterType == typeof(int))
                {
                    decryptors.Add(mi);
                    Console.WriteLine("[host] decryptor candidate token=" + mi.MetadataToken.ToString("X8"));
                }
            }
        }
        if (decryptors.Count == 0) { Console.WriteLine("[host] no decryptor found"); return; }

        var keys = new List<int>();
        foreach (var line in File.ReadAllLines(keysFile))
        {
            int k;
            if (int.TryParse(line.Trim(), out k)) keys.Add(k);
        }
        Console.WriteLine("[host] keys: " + keys.Count + " decryptors: " + decryptors.Count);

        var closed = decryptors.Select(d => d.MakeGenericMethod(typeof(string))).ToArray();
        int ok = 0, nul = 0, fail = 0;
        var errSamples = new List<string>();
        using (var sw = new StreamWriter(outFile, false, Encoding.UTF8))
        {
            foreach (var k in keys)
            {
                string s = null;
                bool got = false;
                foreach (var dec in closed)
                {
                    try
                    {
                        s = (string)dec.Invoke(null, new object[] { k });
                        got = true;
                        if (s != null) break;
                    }
                    catch (Exception ex)
                    {
                        if (errSamples.Count < 8)
                        {
                            var inner = ex.InnerException ?? ex;
                            errSamples.Add("key=" + k + " tok=" + dec.MetadataToken.ToString("X8") + " " + inner.GetType().Name + ": " + inner.Message + "\n" + inner.StackTrace);
                        }
                    }
                }
                if (!got) { fail++; continue; }
                if (s == null) { nul++; continue; }
                sw.Write(k);
                sw.Write('\t');
                sw.WriteLine(s.Replace("\\", "\\\\").Replace("\t", "\\t").Replace("\r", "\\r").Replace("\n", "\\n"));
                ok++;
            }
        }
        Console.WriteLine("[host] ok=" + ok + " null=" + nul + " fail=" + fail);
        foreach (var e in errSamples) Console.WriteLine("[host] ERR " + e);
    }
}
