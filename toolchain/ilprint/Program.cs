using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Program
{
    static Dictionary<int, string> smap = new();

    static void Main(string[] args)
    {
        string asmPath = args[0];
        string mapPath = args[1];
        string filter = args.Length > 2 ? args[2] : "PersonalMethod";

        foreach (var line in File.ReadAllLines(mapPath))
        {
            int i = line.IndexOf('\t');
            if (i > 0 && int.TryParse(line.Substring(0, i), out int k))
                smap[k] = line.Substring(i + 1);
        }

        var mod = ModuleDefMD.Load(asmPath);
        foreach (var t in mod.GetTypes())
        {
            foreach (var m in t.Methods)
            {
                string name = m.Name.String;
                if (!name.Contains(filter) && !t.FullName.Contains(filter)) continue;
                if (m.Body == null) { Console.WriteLine($"== {t.FullName} :: {name} (no body)"); continue; }
                Console.WriteLine($"== METHOD {t.FullName} :: {name}");
                foreach (var ins in m.Body.Instructions)
                {
                    string op = ins.OpCode.Name;
                    string operand = "";
                    switch (ins.Operand)
                    {
                        case IMethod im:
                            operand = im.DeclaringType.FullName + "::" + im.Name;
                            if (im is MethodSpec ms && ms.GenericInstMethodSig != null && ms.GenericInstMethodSig.GenericArguments.Count > 0)
                                operand += "<" + string.Join(",", ms.GenericInstMethodSig.GenericArguments.Select(g => g.ToString())) + ">";
                            break;
                        case IField f: operand = f.DeclaringType.FullName + "::" + f.Name; break;
                        case string s: operand = "\"" + s + "\""; break;
                        case int iv:
                            operand = iv.ToString();
                            if (smap.TryGetValue(iv, out var sv)) operand += $"  [STR: {sv}]";
                            break;
                        case Instruction tgt: operand = tgt.Offset.ToString("X4"); break;
                        case Instruction[] tgts: operand = string.Join(",", tgts.Select(x => x.Offset.ToString("X4"))); break;
                        case ITypeDefOrRef tr: operand = tr.FullName; break;
                        default: operand = ins.Operand?.ToString() ?? ""; break;
                    }
                    // resolve string decryptor calls: pattern ldci4 + call zwXXXX<string>(int)
                    Console.WriteLine($"  {ins.Offset:X4} {op,-12} {operand}");
                }
                Console.WriteLine();
            }
        }
    }
}
