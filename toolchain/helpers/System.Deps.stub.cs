using System;

namespace System.Deps
{
    // Minimal stand-in for the missing Pro licensing assembly, used to test how far
    // the app progresses past the System.Deps FileNotFoundException and whether any
    // blob/activation decryption is triggered. Signatures inferred from koi usage.
    public class Infobase
    {
        private static Infobase _current = new Infobase();
        public static Infobase Current { get { return _current; } }

        public static string pcid { get { return "STUB-PCID-0000"; } }
        public static string w10t { get { return @"Software\Win 10 Tweaker"; } }
        public static string lk { get { return "LicenseKey"; } }
        public static string usershort { get { return "user"; } }
        public static string Public { get { return "<RSAKeyValue></RSAKeyValue>"; } }

        public static bool Decrypt(string input, ref string output)
        {
            output = input; // no-op: real decryption lives in the protector
            return false;
        }

        public static bool Own() { return false; }
        public static void View() { }
    }

    public class Systems
    {
        public static string h { get { return "ValueH"; } }
        public static string l { get { return "ValueL"; } }
        public static bool DefenderDisabled() { return false; }
    }
}
