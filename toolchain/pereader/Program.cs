using System;
using System.IO;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
class P {
    static void Main(string[] args) {
        var bytes = File.ReadAllBytes(args[0]);
        try {
            var pe = new PEReader(new MemoryStream(bytes));
            Console.WriteLine("PE ok hasMetadata=" + pe.HasMetadata);
            var md = pe.GetMetadataReader();
            Console.WriteLine("MD ok typedefs=" + md.TypeDefinitions.Count + " methods=" + md.MethodDefinitions.Count);
        } catch (Exception ex) {
            Console.WriteLine(ex.ToString());
        }
    }
}

