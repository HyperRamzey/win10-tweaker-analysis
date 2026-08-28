using System;
using System.Collections;
using System.IO;
using System.Resources;

class ResDump
{
    static void Main(string[] args)
    {
        string src = args[0];
        string outDir = args[1];
        Directory.CreateDirectory(outDir);
        using (var fs = File.OpenRead(src))
        using (var rr = new ResourceReader(fs))
        {
            foreach (DictionaryEntry e in rr)
            {
                string name = e.Key.ToString();
                object val = e.Value;
                string safe = Sanitize(name);
                byte[] b = val as byte[];
                string s = val as string;
                MemoryStream ms = val as MemoryStream;
                if (b != null)
                {
                    File.WriteAllBytes(Path.Combine(outDir, safe + ".bin"), b);
                    Console.WriteLine("[BYTES] " + name + " len=" + b.Length);
                }
                else if (s != null)
                {
                    File.WriteAllText(Path.Combine(outDir, safe + ".txt"), s);
                    Console.WriteLine("[STR  ] " + name + " len=" + s.Length);
                }
                else if (ms != null)
                {
                    File.WriteAllBytes(Path.Combine(outDir, safe + ".bin"), ms.ToArray());
                    Console.WriteLine("[MSTRM] " + name + " len=" + ms.Length);
                }
                else
                {
                    Console.WriteLine("[? " + (val == null ? "null" : val.GetType().Name) + "] " + name);
                }
            }
        }
    }
    static string Sanitize(string n)
    {
        foreach (char c in Path.GetInvalidFileNameChars()) n = n.Replace(c, '_');
        if (n.Length > 80) n = n.Substring(0, 80);
        return n;
    }
}
