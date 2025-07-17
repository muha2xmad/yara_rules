rule mal_RedLine {
    meta:
        description = "Detects RedLine Stealer"
        author = "Muhammad Hasan Ali @muha2xmad"
        date = "15-07-2025"
        hash1 = "13e9042f6fa0c525b1cbe97d3273b1c0ae0b63e426ffaeec7caa3e11786141f2"
    strings:
            $str1 = "Pseudish" fullword wide
            $str2 = "[^\\u0020-\\u007F]UNKNOWN" fullword wide
            $str3 = "CoCryptographyokieCryptographysN" fullword wide
            $str4 = "cstringmstringd" fullword wide

            $meth1 = {72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 17 80 ?? ?? ?? ?? 2A}
            //\* 72 F2070070   */ IL_0000: ldstr     "Mh4jDAUxKRgzKzMPBTE6HTU7CUMrAxQf"
            //80 04000004   */ IL_0005: stsfld    string Arguments::IP
            //72 34080070   */ IL_000A: ldstr     "ATYoDzEsSxEdGSBI"
            //80 05000004   */ IL_000F: stsfld    string Arguments::ID
            //72 56080070   */ IL_0014: ldstr     ""
            //80 06000004   */ IL_0019: stsfld    string Arguments::Message
            //72 58080070   */ IL_001E: ldstr     "Pseudish"
            //80 07000004   */ IL_0023: stsfld    string Arguments::Key
            //17           */ IL_0028: ldc.i4.1
            //80 08000004   */ IL_0029: stsfld    int32 Arguments::Version
            //2A           */ IL_002E: ret*/

            $meth2 = {25 16 72 ?? ?? ?? ?? A2 25 17 28 ?? ?? ?? ??}
            //25           */ IL_0045: dup
            //16           */ IL_0046: ldc.i4.0
            //72 B4080070   */ IL_0047: ldstr     "\n"
            //A2           */ IL_004C: stelem.ref
            //25           */ IL_004D: dup
            //17           */ IL_004E: ldc.i4.1

            $rep = {02 28 ??  ?? ?? ?? 72 ??  ?? ?? ?? 72 ??  ?? ?? ?? 7E ??  ?? ?? ?? 28 ??  ?? ?? ??}
            //02            */ IL_0006: ldarg.0
            //28 6D00000A   */ IL_0007: call      string [mscorlib]System.Environment::get_SystemDirectory()
            //72 81030070   */ IL_000C: ldstr     "bcrstring.Replaceypt.dstring.Replacell"
            //72 CF030070   */ IL_0011: ldstr     "string.Replace"
            //7E 1E00000A   */ IL_0016: ldsfld    string [mscorlib]System.String::Empty
            //28 1F00000A   */ IL_001B: call      instance string [mscorlib]System.String::Replace(string, string)


    condition:
        uint16(0) == 0x5a4d and $rep and (1 of ($meth*)) and (2 of ($str*))
}


rule mal_RedLine {
    meta:
        description = "Detects RedLine Stealer"
        author = "Muhammad Hasan Ali @muha2xmad"
        date = "15-07-2025"
        hash1 = "13e9042f6fa0c525b1cbe97d3273b1c0ae0b63e426ffaeec7caa3e11786141f2"
    strings:
            $str1 = "Pseudish" fullword wide
            $str2 = "[^\\u0020-\\u007F]UNKNOWN" fullword wide
            $str3 = "CoCryptographyokieCryptographysN" fullword wide
            $str4 = "cstringmstringd" fullword wide


    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

